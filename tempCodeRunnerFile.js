// =====================================================
// Arche Vault - Single File (All-in-One) with Auto-Migrations
// Run: node app.js
// Dependencies:
//   npm install express cors body-parser better-sqlite3 jsonwebtoken bcryptjs
// =====================================================

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

// -------- Config ----------
const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const PORT = process.env.PORT || 4000;
const SIMULATION_INTERVAL_MS = 30 * 1000; // demo interval (30s)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const DB_PATH = path.join(__dirname, "archevault.db");

// -------- Init DB with migrations-safe logic ----------
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);

// Helper: check if table exists
function tableExists(name) {
  const r = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").get(name);
  return !!r;
}
// Helper: get columns for a table
function getColumns(table) {
  try {
    const rows = db.prepare(`PRAGMA table_info(${table})`).all();
    return rows.map(r => r.name);
  } catch (e) { return []; }
}
// Create baseline tables if missing
const baselineSQL = `CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  amount REAL,
  frequency TEXT,
  duration INTEGER,
  status TEXT,
  progress REAL DEFAULT 0,
  total_contributions REAL DEFAULT 0,
  next_contribution DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contributions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER,
  user_id INTEGER,
  amount REAL,
  contributed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  note TEXT
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  message TEXT,
  read INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT,
  meta TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT,
  message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`;
db.exec(baselineSQL);

// Auto-migration helper: add column if missing
function addColumnIfMissing(table, columnName, definition) {
  const cols = getColumns(table);
  if (!cols.includes(columnName)) {
    console.log(`Migrating: adding column ${columnName} to ${table}`);
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${columnName} ${definition}`).run();
  }
}

// Apply migrations safely (non-destructive)
addColumnIfMissing("users", "is_admin", "INTEGER DEFAULT 0");
addColumnIfMissing("plans", "description", "TEXT");
addColumnIfMissing("plans", "currency", "TEXT DEFAULT 'BTC'");
addColumnIfMissing("users", "display_name", "TEXT");
addColumnIfMissing("notifications", "level", "TEXT DEFAULT 'info'");

// Ensure admin user exists (create if missing)
(function ensureAdmin() {
  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(ADMIN_USERNAME);
  if (!exists) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare("INSERT INTO users (username, password_hash, is_admin, display_name) VALUES (?, ?, 1, ?)").run(ADMIN_USERNAME, hash, "Administrator");
    console.log("Created default admin user:", ADMIN_USERNAME);
  }
})();

// -------- Helpers ----------
function issueJwt(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: "7d" });
}
function verifyJwt(token) {
  try { return jwt.verify(token, SECRET); } catch { return null; }
}
function nowISO() { return new Date().toISOString(); }
function daysFromNowISO(days) { return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString(); }
function logAudit(userId, action, meta = "") {
  try { db.prepare("INSERT INTO audit_logs (user_id, action, meta) VALUES (?, ?, ?)").run(userId || null, action, meta); } catch(e) { console.error("audit failed", e); }
}
function frequencyNextDays(freq) {
  if (freq === "daily") return 1;
  if (freq === "weekly") return 7;
  return 30;
}

// -------- Express init ----------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// -------- Auth middleware (applies to non-public routes) ----------
app.use((req, res, next) => {
  // public endpoints
  if (req.path.startsWith("/api/auth") || req.path === "/" || req.path.startsWith("/static/") || req.path.startsWith("/_health") || req.path.startsWith("/public/")) return next();
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "missing authorization" });
  const parts = header.split(" ");
  if (parts.length !== 2) return res.status(401).json({ error: "invalid authorization" });
  const payload = verifyJwt(parts[1]);
  if (!payload) return res.status(401).json({ error: "invalid token" });
  req.user = payload;
  next();
});

// -------- Routes ----------

// Health
app.get("/_health", (req, res) => res.json({ ok: true, now: nowISO() }));

// --- Auth ---
app.post("/api/auth/register", (req, res) => {
  try {
    const { username, password, display_name } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username & password required" });
    const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
    if (exists) return res.status(400).json({ error: "username taken" });
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare("INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)").run(username, hash, display_name || username);
    logAudit(info.lastInsertRowid, "user.register", JSON.stringify({ username }));
    res.json({ success: true, message: "registered" });
  } catch (err) {
    console.error("register err", err); res.status(500).json({ error: "internal error" });
  }
});

app.post("/api/auth/login", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username & password required" });
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "invalid credentials" });
    const token = issueJwt({ userId: user.id, username: user.username, isAdmin: !!user.is_admin });
    logAudit(user.id, "user.login");
    res.json({ token, username: user.username, displayName: user.display_name, isAdmin: !!user.is_admin });
  } catch (err) {
    console.error("login err", err); res.status(500).json({ error: "internal error" });
  }
});

// --- Profile ---
app.get("/api/profile", (req, res) => {
  try {
    const user = db.prepare("SELECT id, username, display_name, is_admin, created_at FROM users WHERE id = ?").get(req.user.userId);
    const plans = db.prepare("SELECT COUNT(*) as count FROM plans WHERE user_id = ? AND status = 'active'").get(req.user.userId);
    const saved = db.prepare("SELECT SUM(progress) as total FROM plans WHERE user_id = ?").get(req.user.userId);
    res.json({ user, stats: { activePlans: plans.count || 0, saved: saved.total || 0 } });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

app.post("/api/profile/update", (req, res) => {
  try {
    const { username: newUsername, display_name } = req.body || {};
    if (!newUsername && !display_name) return res.status(400).json({ error: "nothing to update" });
    if (newUsername) {
      const exists = db.prepare("SELECT id FROM users WHERE username = ? AND id != ?").get(newUsername, req.user.userId);
      if (exists) return res.status(400).json({ error: "username taken" });
      db.prepare("UPDATE users SET username = ? WHERE id = ?").run(newUsername, req.user.userId);
      logAudit(req.user.userId, "profile.update_username", JSON.stringify({ newUsername }));
    }
    if (typeof display_name !== "undefined") {
      db.prepare("UPDATE users SET display_name = ? WHERE id = ?").run(display_name, req.user.userId);
      logAudit(req.user.userId, "profile.update_display", JSON.stringify({ display_name }));
    }
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

app.post("/api/profile/change-password", (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) return res.status(400).json({ error: "oldPassword & newPassword required" });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.userId);
    if (!user) return res.status(404).json({ error: "user not found" });
    const valid = bcrypt.compareSync(oldPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: "invalid old password" });
    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.userId);
    logAudit(req.user.userId, "profile.change_password");
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

// --- Plans ---
app.get("/api/plans", (req, res) => {
  try {
    const plans = db.prepare("SELECT * FROM plans WHERE user_id = ? ORDER BY created_at DESC").all(req.user.userId);
    res.json(plans);
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

app.post("/api/plans", (req, res) => {
  try {
    const { amount, frequency, duration, description, currency } = req.body || {};
    if (!amount || !frequency || !duration) return res.status(400).json({ error: "missing fields" });
    const multiplier = frequency === "daily" ? 30 : frequency === "weekly" ? 4 : 1;
    const total = parseFloat(amount) * multiplier * parseInt(duration);
    const nextDays = frequencyNextDays(frequency);
    const nextContribution = daysFromNowISO(nextDays);
    const info = db.prepare(`INSERT INTO plans (user_id, amount, frequency, duration, status, total_contributions, next_contribution, description, currency) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`)
      .run(req.user.userId, amount, frequency, duration, total, nextContribution, description || null, currency || "BTC");
    const plan = db.prepare("SELECT * FROM plans WHERE id = ?").get(info.lastInsertRowid);
    db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(req.user.userId, `Plan #${plan.id} created: ${amount} ${frequency} for ${duration} months`);
    logAudit(req.user.userId, "plan.create", JSON.stringify(plan));
    res.json(plan);
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

app.patch("/api/plans/:id", (req, res) => {
  try {
    const { action, progress } = req.body || {};
    const id = req.params.id;
    const plan = db.prepare("SELECT * FROM plans WHERE id = ? AND user_id = ?").get(id, req.user.userId);
    if (!plan) return res.status(404).json({ error: "plan not found" });

    if (action === "pause") {
      const newStatus = plan.status === "active" ? "paused" : "active";
      db.prepare("UPDATE plans SET status = ? WHERE id = ?").run(newStatus, id);
      db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(req.user.userId, `Plan #${id} ${newStatus}`);
      logAudit(req.user.userId, "plan.toggle_pause", JSON.stringify({ planId: id, status: newStatus }));
    } else if (action === "withdraw") {
      db.prepare("UPDATE plans SET status = 'withdrawn' WHERE id = ?").run(id);
      db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(req.user.userId, `Plan #${id} withdrawn`);
      logAudit(req.user.userId, "plan.withdraw", JSON.stringify({ planId: id }));
    } else if (action === "delete") {
      db.prepare("DELETE FROM contributions WHERE plan_id = ?").run(id);
      db.prepare("DELETE FROM plans WHERE id = ? AND user_id = ?").run(id, req.user.userId);
      logAudit(req.user.userId, "plan.delete", JSON.stringify({ planId: id }));
    } else if (typeof progress === "number") {
      db.prepare("UPDATE plans SET progress = ? WHERE id = ?").run(progress, id);
      logAudit(req.user.userId, "plan.set_progress", JSON.stringify({ planId: id, progress }));
    } else {
      return res.status(400).json({ error: "invalid action" });
    }
    const updated = db.prepare("SELECT * FROM plans WHERE id = ?").get(id);
    res.json(updated || { success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

// --- Contributions & Transactions ---
app.get("/api/transactions", (req, res) => {
  try {
    const txs = db.prepare("SELECT * FROM contributions WHERE user_id = ? ORDER BY contributed_at DESC").all(req.user.userId);
    res.json(txs);
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

app.post("/api/contribute", (req, res) => {
  try {
    const { planId, amount, note } = req.body || {};
    if (!planId || !amount) return res.status(400).json({ error: "planId & amount required" });
    const plan = db.prepare("SELECT * FROM plans WHERE id = ? AND user_id = ?").get(planId, req.user.userId);
    if (!plan) return res.status(404).json({ error: "plan not found" });
    const info = db.prepare("INSERT INTO contributions (plan_id, user_id, amount, note) VALUES (?, ?, ?, ?)").run(planId, req.user.userId, amount, note || "");
    const newProgress = (plan.progress || 0) + parseFloat(amount);
    const nextContribution = daysFromNowISO(frequencyNextDays(plan.frequency));
    db.prepare("UPDATE plans SET progress = ?, next_contribution = ? WHERE id = ?").run(newProgress, nextContribution, planId);
    db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(req.user.userId, `Manual contribution of ${amount} recorded for Plan #${planId}`);
    logAudit(req.user.userId, "contribution.manual", JSON.stringify({ planId, amount, note }));
    const tx = db.prepare("SELECT * FROM contributions WHERE id = ?").get(info.lastInsertRowid);
    res.json(tx);
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

// --- Notifications ---
app.get("/api/notifications", (req, res) => {
  try {
    const notes = db.prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 200").all(req.user.userId);
    res.json(notes);
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});
app.post("/api/notifications/:id/read", (req, res) => {
  try {
    const id = req.params.id;
    db.prepare("UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?").run(id, req.user.userId);
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

// --- Contact (public) ---
app.post("/api/contact", (req, res) => {
  try {
    const { name, email, message } = req.body || {};
    if (!name || !email || !message) return res.status(400).json({ error: "name, email, message required" });
    const info = db.prepare("INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)").run(name, email, message);
    // notify admins
    const admins = db.prepare("SELECT id FROM users WHERE is_admin = 1").all();
    admins.forEach(a => {
      db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(a.id, `Contact from ${name} <${email}>: ${message.slice(0, 120)}`);
    });
    logAudit(null, "contact.submitted", JSON.stringify({ id: info.lastInsertRowid, name, email }));
    res.json({ success: true, message: "thanks" });
  } catch (err) { console.error(err); res.status(500).json({ error: "internal error" }); }
});

// --- Admin endpoints ---
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: "admin only" });
  next();
}

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, display_name, is_admin, created_at FROM users ORDER BY created_at DESC").all();
  res.json(users);
});
app.post("/api/admin/user/:id/promote", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(id);
  logAudit(req.user.userId, "admin.promote", JSON.stringify({ targetId: id }));
  res.json({ success: true });
});
app.post("/api/admin/user/:id/demote", requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  db.prepare("UPDATE users SET is_admin = 0 WHERE id = ?").run(id);
  logAudit(req.user.userId, "admin.demote", JSON.stringify({ targetId: id }));
  res.json({ success: true });
});

app.get("/api/admin/stats", requireAdmin, (req, res) => {
  const totalUsers = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  const totalPlans = db.prepare("SELECT COUNT(*) as c FROM plans").get().c;
  const totalActive = db.prepare("SELECT COUNT(*) as c FROM plans WHERE status = 'active'").get().c;
  const totalSaved = db.prepare("SELECT SUM(progress) as s FROM plans").get().s || 0;
  const recentContributions = db.prepare("SELECT * FROM contributions ORDER BY contributed_at DESC LIMIT 50").all();
  res.json({ totalUsers, totalPlans, totalActive, totalSaved, recentContributions });
});

app.get("/api/admin/audit", requireAdmin, (req, res) => {
  const logs = db.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").all();
  res.json(logs);
});

app.get("/api/admin/export/users", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT id, username, display_name, is_admin, created_at FROM users ORDER BY id ASC").all();
  const header = "id,username,display_name,is_admin,created_at\n";
  const csv = header + rows.map(r => `${r.id},"${r.username}","${r.display_name||''}",${r.is_admin},"${r.created_at}"`).join("\n");
  res.setHeader("Content-Disposition", 'attachment; filename="users.csv"');
  res.setHeader("Content-Type", "text/csv");
  res.send(csv);
  logAudit(req.user.userId, "admin.export.users");
});

app.get("/api/admin/export/transactions", requireAdmin, (req, res) => {
  const { from, to } = req.query || {};
  let rows;
  if (from || to) {
    const fromQ = from ? new Date(from).toISOString() : "1970-01-01T00:00:00.000Z";
    const toQ = to ? new Date(to).toISOString() : new Date().toISOString();
    rows = db.prepare("SELECT * FROM contributions WHERE contributed_at BETWEEN ? AND ? ORDER BY id ASC").all(fromQ, toQ);
  } else {
    rows = db.prepare("SELECT * FROM contributions ORDER BY id ASC").all();
  }
  const header = "id,plan_id,user_id,amount,contributed_at,note\n";
  const csv = header + rows.map(r => `${r.id},${r.plan_id},${r.user_id},${r.amount},"${r.contributed_at}","${(r.note||"").replace(/\"/g,'""')}"`).join("\n");
  res.setHeader("Content-Disposition", 'attachment; filename="transactions.csv"');
  res.setHeader("Content-Type", "text/csv");
  res.send(csv);
  logAudit(req.user.userId, "admin.export.transactions");
});

app.get("/api/admin/backup/db", requireAdmin, (req, res) => {
  if (!fs.existsSync(DB_PATH)) return res.status(404).json({ error: "db not found" });
  res.download(DB_PATH, "archevault.db");
  logAudit(req.user.userId, "admin.backup.db");
});

app.post("/api/admin/force-simulate", requireAdmin, (req, res) => {
  simulateStep();
  logAudit(req.user.userId, "admin.force_simulate");
  res.json({ success: true, now: nowISO() });
});

// --- Simulation: process scheduled contributions ---
function simulateStep() {
  try {
    const nowIso = new Date().toISOString();
    const duePlans = db.prepare("SELECT * FROM plans WHERE status = 'active' AND next_contribution <= ?").all(nowIso);
    duePlans.forEach(plan => {
      const amount = parseFloat(plan.amount);
      db.prepare("INSERT INTO contributions (plan_id, user_id, amount, note) VALUES (?, ?, ?, ?)").run(plan.id, plan.user_id, amount, "Automated scheduled contribution");
      const newProgress = (plan.progress || 0) + amount;
      const nextDays = frequencyNextDays(plan.frequency);
      const nextContribution = daysFromNowISO(nextDays);
      db.prepare("UPDATE plans SET progress = ?, next_contribution = ? WHERE id = ?").run(newProgress, nextContribution, plan.id);
      db.prepare("INSERT INTO notifications (user_id, message) VALUES (?, ?)").run(plan.user_id, `Automated deposit ${amount} for Plan #${plan.id} completed`);
      logAudit(plan.user_id, "contribution.auto", JSON.stringify({ planId: plan.id, amount, nextContribution }));
    });
  } catch (err) { console.error("simulateStep error", err); }
}
setInterval(simulateStep, SIMULATION_INTERVAL_MS);
setTimeout(simulateStep, 2000);

// --- Frontend: single-page app served at / ---
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arche Vault</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>.toast{position:fixed;right:20px;bottom:20px;z-index:60}</style>
</head><body class="bg-gray-50 text-gray-900 antialiased">
<!-- Simple SPA UI -->
<nav class="bg-white shadow">
  <div class="max-w-6xl mx-auto px-4 py-3 flex justify-between items-center">
    <div class="text-2xl font-bold text-blue-600">Arche Vault</div>
    <div id="navRight" class="flex items-center space-x-3">
      <div id="authButtons" class="flex items-center space-x-2">
        <button id="loginBtn" class="px-4 py-2 bg-blue-600 text-white rounded">Login</button>
        <button id="registerBtn" class="px-3 py-2 border rounded">Register</button>
      </div>
      <div id="userMenu" class="hidden items-center space-x-2">
        <div id="notifBell" class="relative p-2 cursor-pointer"><i class="fa-solid fa-bell"></i><span id="notifCount" class="hidden absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full px-1">0</span></div>
        <div id="userPeek" class="flex items-center space-x-2 p-2 cursor-pointer"><i class="fa-solid fa-user text-blue-600"></i><span id="usernameDisplay" class="font-semibold"></span></div>
        <button id="logoutBtn" class="px-3 py-1 bg-red-500 text-white rounded">Logout</button>
      </div>
    </div>
  </div>
</nav>

<header class="py-12 bg-blue-50">
  <div class="max-w-6xl mx-auto px-4 grid md:grid-cols-2 gap-6 items-center">
    <div>
      <h1 class="text-4xl font-bold">Automated Savings Demo</h1>
      <p class="mt-2 text-gray-700">Create plans, simulate contributions, view charts, export CSVs, and use admin tools.</p>
      <div class="mt-4"><button id="createPlanBtn" class="px-4 py-2 bg-blue-600 text-white rounded">Create Plan</button></div>
    </div>
    <div class="bg-white p-4 rounded shadow">
      <canvas id="heroChart" class="h-48 w-full"></canvas>
    </div>
  </div>
</header>

<main id="app" class="max-w-6xl mx-auto px-4 py-8 hidden">
  <div class="grid md:grid-cols-4 gap-6">
    <div class="md:col-span-3">
      <div class="bg-white p-4 rounded shadow mb-4">
        <div class="flex justify-between items-center">
          <h2 class="font-bold">Dashboard</h2>
          <div><button id="refreshBtn" class="px-3 py-1 border rounded">Refresh</button></div>
        </div>
        <div class="mt-4 grid md:grid-cols-3 gap-4">
          <div class="p-3 border rounded"><div class="text-xs text-gray-500">Total Saved</div><div id="statSaved" class="text-2xl font-bold">0 BTC</div></div>
          <div class="p-3 border rounded"><div class="text-xs text-gray-500">Active Plans</div><div id="statActive" class="text-2xl font-bold">0</div></div>
          <div class="p-3 border rounded"><div class="text-xs text-gray-500">Notifications</div><div id="statNotif" class="text-2xl font-bold">0</div></div>
        </div>
        <div class="mt-4">
          <canvas id="mainChart" class="w-full h-64 bg-white rounded"></canvas>
        </div>
      </div>

      <div class="bg-white p-4 rounded shadow mb-4">
        <div class="flex justify-between items-center"><h3 class="font-bold">My Plans</h3><div></div></div>
        <div id="plansList" class="mt-4 space-y-3"></div>
      </div>

      <div class="bg-white p-4 rounded shadow">
        <h3 class="font-bold">Recent Transactions</h3>
        <div id="txList" class="mt-2"></div>
      </div>
    </div>

    <aside class="bg-white p-4 rounded shadow">
      <h4 class="font-bold">Profile</h4>
      <div class="mt-3"><div class="text-xs text-gray-500">User</div><div id="profileName" class="font-semibold">—</div></div>
      <div class="mt-3"><div class="text-xs text-gray-500">Saved</div><div id="profileSaved" class="font-semibold">—</div></div>
      <div id="adminPanel" class="mt-4 hidden">
        <h5 class="font-semibold">Admin</h5>
        <div class="mt-2 space-y-2">
          <button id="adminStatsBtn" class="w-full p-2 border rounded">Admin Stats</button>
          <button id="exportUsersBtn" class="w-full p-2 bg-blue-600 text-white rounded">Export Users</button>
          <button id="exportTxBtn" class="w-full p-2 bg-green-600 text-white rounded">Export Transactions</button>
          <button id="forceSimBtn" class="w-full p-2 bg-yellow-500 text-white rounded">Force Sim</button>
          <button id="dbBackupBtn" class="w-full p-2 border rounded">Download DB</button>
        </div>
        <div id="adminArea" class="mt-3 text-xs"></div>
      </div>
      <div class="mt-4"><h5 class="font-semibold">Notifications</h5><div id="miniNotifs" class="mt-2"></div></div>
    </aside>
  </div>
</main>

<div id="modalRoot"></div>
<div id="toastRoot" class="toast"></div>

<script>
// ---------- Client JS ----------
const API_BASE = "";
let token = null;
let username = null;
let isAdmin = false;
let mainChart=null, heroChart=null;

function api(path, method='GET', body) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(API_BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined }).then(async r => {
    const txt = await r.text();
    try { return JSON.parse(txt); } catch { return txt; }
  });
}
function toast(msg, ms=3500) {
  const root = document.getElementById('toastRoot');
  const el = document.createElement('div');
  el.className = 'bg-white p-3 rounded shadow mb-2 border';
  el.innerText = msg;
  root.appendChild(el);
  setTimeout(()=>el.remove(), ms);
}
function openModal(html) {
  document.getElementById('modalRoot').innerHTML = '<div class="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50" id="modalBack"><div class="bg-white p-6 rounded max-w-lg w-full">' + html + '</div></div>';
  document.getElementById('modalBack').onclick = (e) => { if (e.target.id === 'modalBack') document.getElementById('modalRoot').innerHTML = ''; };
}
function closeModal(){ document.getElementById('modalRoot').innerHTML = ''; }

// Auth UI
document.getElementById('loginBtn').onclick = ()=> {
  openModal('<h3 class="font-bold mb-2">Login</h3><input id="l_user" class="w-full p-2 border rounded mb-2" placeholder="username"/><input id="l_pass" type="password" class="w-full p-2 border rounded mb-4" placeholder="password"/><div class="flex justify-end"><button id="doLogin" class="px-4 py-2 bg-blue-600 text-white rounded">Login</button></div>');
  document.getElementById('doLogin').onclick = async ()=> {
    const u = document.getElementById('l_user').value, p = document.getElementById('l_pass').value;
    const res = await api('/api/auth/login','POST',{ username:u, password:p });
    if (res.token) { token = res.token; username = res.username; isAdmin = res.isAdmin || false; localStorage.setItem('arche_token', token); localStorage.setItem('arche_user', username); document.getElementById('modalRoot').innerHTML=''; onLogin(); toast('Welcome '+username); } else toast('Login failed: '+(res.error||'unknown'));
  };
};
document.getElementById('registerBtn').onclick = ()=> {
  openModal('<h3 class="font-bold mb-2">Register</h3><input id="r_user" class="w-full p-2 border rounded mb-2" placeholder="username"/><input id="r_pass" type="password" class="w-full p-2 border rounded mb-4" placeholder="password"/><div class="flex justify-end"><button id="doReg" class="px-4 py-2 bg-green-600 text-white rounded">Register</button></div>');
  document.getElementById('doReg').onclick = async ()=> {
    const u = document.getElementById('r_user').value, p = document.getElementById('r_pass').value;
    const res = await api('/api/auth/register','POST',{ username:u, password:p });
    if (res.success) { toast('Registered. Please login.'); closeModal(); } else toast('Register failed: '+(res.error||'unknown'));
  };
};

document.getElementById('logoutBtn').onclick = ()=> { token=null; username=null; isAdmin=false; localStorage.removeItem('arche_token'); localStorage.removeItem('arche_user'); location.reload(); };

document.getElementById('createPlanBtn').onclick = ()=> openCreatePlan();

function openCreatePlan() {
  openModal('<h3 class="font-bold mb-2">Create Plan</h3><input id="p_amount" class="w-full p-2 border rounded mb-2" placeholder="Amount (BTC)"/><select id="p_freq" class="w-full p-2 border rounded mb-2"><option value="daily">Daily</option><option value="weekly" selected>Weekly</option><option value="monthly">Monthly</option></select><input id="p_dur" class="w-full p-2 border rounded mb-4" placeholder="Duration (months)"/><div class="flex justify-end"><button id="p_create" class="px-4 py-2 bg-blue-600 text-white rounded">Create</button></div>');
  document.getElementById('p_create').onclick = async ()=> {
    const amount = parseFloat(document.getElementById('p_amount').value);
    const frequency = document.getElementById('p_freq').value;
    const duration = parseInt(document.getElementById('p_dur').value);
    if (!amount || !frequency || !duration) { toast('Fill all fields'); return; }
    const res = await api('/api/plans','POST',{ amount, frequency, duration });
    if (res && res.id) { toast('Plan created'); closeModal(); refreshAll(); } else toast('Create failed: '+(res.error||'unknown'));
  };
}

// On login
async function onLogin() {
  document.getElementById('authButtons').classList.add('hidden');
  document.getElementById('userMenu').classList.remove('hidden');
  document.getElementById('usernameDisplay').innerText = username || 'You';
  document.getElementById('app').classList.remove('hidden');
  if (isAdmin) document.getElementById('adminPanel').classList.remove('hidden');
  await refreshAll();
}

// Restore token if any
(function restore(){ const t = localStorage.getItem('arche_token'); const u = localStorage.getItem('arche_user'); if (t && u) { token = t; username = u; api('/api/profile').then(()=> onLogin()).catch(()=>{}); } })();

// Data loaders
async function refreshAll() {
  if (!token) return;
  await Promise.all([loadProfile(), loadPlans(), loadTx(), loadNotifs(), loadCharts()]);
}
async function loadProfile() {
  const res = await api('/api/profile');
  if (res && res.user) {
    document.getElementById('profileName').innerText = res.user.display_name || res.user.username;
    document.getElementById('profileSaved').innerText = (res.stats.saved||0).toFixed(2) + ' BTC';
  }
}
async function loadPlans() {
  const plans = await api('/api/plans');
  const el = document.getElementById('plansList'); el.innerHTML = '';
  if (!Array.isArray(plans)) return;
  document.getElementById('statActive').innerText = plans.filter(p=>p.status==='active').length;
  let total = 0;
  plans.forEach(p => {
    total += p.progress || 0;
    const card = document.createElement('div');
    card.className = 'p-3 border rounded flex justify-between';
    const percent = Math.min(100, ((p.progress||0)/(p.total_contributions||1))*100);
    card.innerHTML = '<div class="flex-1"><div class="flex justify-between"><div><div class="font-semibold">Plan #'+p.id+' • '+p.frequency+'</div><div class="text-sm text-gray-500">Amount: '+p.amount+' • '+p.duration+' mo</div></div><div class="text-right"><div class="font-medium">'+(p.progress||0).toFixed(2)+' / '+(p.total_contributions||0).toFixed(2)+'</div><div class="text-xs text-gray-500">Next: '+(p.next_contribution?new Date(p.next_contribution).toLocaleString():'—')+'</div></div></div><div class="w-full bg-gray-100 h-2 rounded mt-2 overflow-hidden"><div style="width:'+percent+'%" class="h-2 bg-gradient-to-r from-green-400 to-blue-500"></div></div></div>' +
      '<div class="ml-3 flex flex-col space-y-2"><button class="px-3 py-1 border rounded" onclick="togglePlan('+p.id+')">'+(p.status==='active'?'Pause':'Resume')+'</button><button class="px-3 py-1 bg-yellow-500 text-white rounded" onclick="contributeQuick('+p.id+', '+p.amount+')">Contribute</button></div>';
    el.appendChild(card);
  });
  document.getElementById('statSaved').innerText = total.toFixed(2) + ' BTC';
}
async function loadTx() {
  const txs = await api('/api/transactions');
  const el = document.getElementById('txList'); el.innerHTML = '';
  if (!Array.isArray(txs)) return;
  txs.slice(0,50).forEach(tx => {
    const div = document.createElement('div'); div.className = 'flex justify-between items-center p-2 border-b';
    div.innerHTML = '<div><div class="font-medium">Plan #'+tx.plan_id+'</div><div class="text-xs text-gray-500">'+new Date(tx.contributed_at).toLocaleString()+'</div></div><div class="text-right font-semibold">+'+parseFloat(tx.amount).toFixed(2)+'</div>';
    el.appendChild(div);
  });
}
async function loadNotifs() {
  const nots = await api('/api/notifications');
  const el = document.getElementById('miniNotifs'); el.innerHTML = '';
  if (!Array.isArray(nots)) return;
  const unread = nots.filter(n=>n.read===0).length;
  document.getElementById('statNotif').innerText = unread;
  const badge = document.getElementById('notifCount'); if (unread>0) { badge.classList.remove('hidden'); badge.innerText = unread; } else badge.classList.add('hidden');
  nots.slice(0,5).forEach(n => {
    const d = document.createElement('div'); d.className='p-2 border rounded text-sm'; d.innerHTML = '<div>'+n.message+'</div><div class="text-xs text-gray-500">'+new Date(n.created_at).toLocaleString()+'</div>'; el.appendChild(d);
  });
}
async function loadCharts() {
  const plans = await api('/api/plans');
  if (!Array.isArray(plans)) return;
  const labels = plans.map(p=>'Plan '+p.id);
  const data = plans.map(p=>parseFloat(p.progress||0));
  const ctx = document.getElementById('mainChart');
  if (mainChart) mainChart.destroy();
  mainChart = new Chart(ctx, { type: 'line', data: { labels, datasets: [{ label: 'Saved', data, fill: true }] }, options: { responsive: true } });
  const hctx = document.getElementById('heroChart');
  if (heroChart) heroChart.destroy();
  heroChart = new Chart(hctx, { type:'bar', data: { labels, datasets: [{ label:'Progress', data }] }, options: { responsive:true } });
}

// Controls for plan actions
window.togglePlan = async (id) => { const r = await api('/api/plans/'+id,'PATCH',{ action: 'pause' }); if (r) { toast('Toggled'); refreshAll(); } };
window.contributeQuick = async (planId, amount) => { const r = await api('/api/contribute','POST',{ planId, amount, note: 'Quick deposit' }); if (r && r.id) { toast('Contributed'); refreshAll(); } else toast('Error'); };

// Buttons: refresh & admin actions
document.getElementById('refreshBtn').onclick = ()=> refreshAll();
document.getElementById('adminStatsBtn').onclick = async ()=> { const s = await api('/api/admin/stats'); document.getElementById('adminArea').innerHTML = '<pre class="text-xs p-2 bg-gray-50 rounded">'+JSON.stringify(s,null,2)+'</pre>'; };
document.getElementById('exportUsersBtn').onclick = ()=> download('/api/admin/export/users','users.csv');
document.getElementById('exportTxBtn').onclick = ()=> download('/api/admin/export/transactions','transactions.csv');
document.getElementById('forceSimBtn').onclick = async ()=> { const r = await api('/api/admin/force-simulate','POST'); if (r && r.success) { toast('Simulation run'); refreshAll(); } };
document.getElementById('dbBackupBtn').onclick = ()=> download('/api/admin/backup/db','archevault.db');

async function download(url, filename) {
  const headers = {}; if (token) headers['Authorization'] = 'Bearer ' + token;
  const r = await fetch(url, { headers }); if (!r.ok) { toast('Download failed'); return; }
  const blob = await r.blob(); const a = document.createElement('a'); const urlObj = URL.createObjectURL(blob);
  a.href = urlObj; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(urlObj); toast('Download started: '+filename);
}

// Periodic refresh
setInterval(()=>{ if (token) refreshAll(); }, 20000);

// Initial UI state: hide app
document.getElementById('app').classList.add('hidden');

// End client script
</script>

</body></html>`);
});

// Start server
app.listen(PORT, () => {
  console.log("Arche Vault running on http://localhost:" + PORT);
  console.log("DB path:", DB_PATH);
  console.log("Simulation interval (ms):", SIMULATION_INTERVAL_MS);
});
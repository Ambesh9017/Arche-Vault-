// =====================================================
// Enhanced Arche Vault - Complete Application
// Features: Savings Plans, Crypto Support, Admin Dashboard, 
// Analytics, Security, and Modern UI
// =====================================================

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// -------- Enhanced Configuration ----------
const config = {
  secret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  port: process.env.PORT || 4000,
  simulationInterval: 60 * 1000, // 1 minute for demo
  adminUsername: process.env.ADMIN_USERNAME || "admin",
  adminPassword: process.env.ADMIN_PASSWORD || "admin123",
  dbPath: path.join(__dirname, "archevault.db"),
  maxLoginAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
  currencies: ['BTC', 'ETH', 'USD', 'EUR'],
  planTypes: ['savings', 'emergency', 'retirement', 'investment'],
  notificationLevels: ['info', 'warning', 'success', 'error']
};

// -------- Enhanced Database Setup ----------
fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
const db = new Database(config.dbPath);

function tableExists(name) {
  const r = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").get(name);
  return !!r;
}

function getColumns(table) {
  try {
    const rows = db.prepare(`PRAGMA table_info(${table})`).all();
    return rows.map(r => r.name);
  } catch (e) { return []; }
}

// Enhanced baseline schema
const enhancedSchema = `
-- Users with security features
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  is_admin INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  login_attempts INTEGER DEFAULT 0,
  locked_until DATETIME,
  two_factor_secret TEXT,
  two_factor_enabled INTEGER DEFAULT 0,
  avatar_url TEXT,
  timezone TEXT DEFAULT 'UTC',
  preferences TEXT DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Enhanced plans with categories and goals
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  plan_type TEXT DEFAULT 'savings',
  amount REAL NOT NULL,
  frequency TEXT NOT NULL,
  duration INTEGER NOT NULL,
  currency TEXT DEFAULT 'BTC',
  target_amount REAL,
  status TEXT DEFAULT 'active',
  priority INTEGER DEFAULT 1,
  auto_contribute INTEGER DEFAULT 1,
  progress REAL DEFAULT 0,
  total_contributions REAL DEFAULT 0,
  next_contribution DATETIME,
  completion_date DATETIME,
  tags TEXT DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Enhanced contributions with categories
CREATE TABLE IF NOT EXISTS contributions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  transaction_type TEXT DEFAULT 'deposit',
  payment_method TEXT DEFAULT 'auto',
  transaction_hash TEXT,
  fee REAL DEFAULT 0,
  note TEXT,
  contributed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans (id),
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Enhanced notifications with levels and categories
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT,
  message TEXT NOT NULL,
  level TEXT DEFAULT 'info',
  category TEXT DEFAULT 'general',
  read INTEGER DEFAULT 0,
  action_url TEXT,
  expires_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Enhanced audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  metadata TEXT DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Contact messages with status
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT,
  message TEXT NOT NULL,
  status TEXT DEFAULT 'new',
  assigned_to INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (assigned_to) REFERENCES users (id)
);

-- System settings
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  value TEXT NOT NULL,
  description TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User sessions for security
CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Goals and milestones
CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  plan_id INTEGER,
  title TEXT NOT NULL,
  description TEXT,
  target_amount REAL NOT NULL,
  target_date DATETIME,
  status TEXT DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id),
  FOREIGN KEY (plan_id) REFERENCES plans (id)
);
`;

db.exec(enhancedSchema);

// Auto-migration helper
function addColumnIfMissing(table, columnName, definition) {
  const cols = getColumns(table);
  if (!cols.includes(columnName)) {
    console.log(`Migrating: adding column ${columnName} to ${table}`);
    try {
      db.prepare(`ALTER TABLE ${table} ADD COLUMN ${columnName} ${definition}`).run();
    } catch (e) {
      console.error(`Migration failed: ${e.message}`);
    }
  }
}

// Apply additional migrations
const migrations = [
  ['users', 'last_login', 'DATETIME'],
  ['plans', 'risk_level', 'TEXT DEFAULT "low"'],
  ['contributions', 'status', 'TEXT DEFAULT "completed"'],
  ['notifications', 'metadata', 'TEXT DEFAULT "{}"']
];

migrations.forEach(([table, column, definition]) => {
  addColumnIfMissing(table, column, definition);
});

// Create indices for performance
const indices = [
  'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
  'CREATE INDEX IF NOT EXISTS idx_plans_user_id ON plans(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_contributions_plan_id ON contributions(plan_id)',
  'CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_plans_status ON plans(status)',
  'CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read)'
];

indices.forEach(sql => {
  try { db.exec(sql); } catch (e) { /* ignore if exists */ }
});

// Ensure admin user exists
(function ensureAdmin() {
  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(config.adminUsername);
  if (!exists) {
    const hash = bcrypt.hashSync(config.adminPassword, 12);
    db.prepare(`INSERT INTO users (username, password_hash, is_admin, display_name, email) 
                 VALUES (?, ?, 1, ?, ?)`).run(
      config.adminUsername, 
      hash, 
      "System Administrator",
      "admin@archevault.com"
    );
    console.log("✅ Created default admin user:", config.adminUsername);
  }
})();

// Insert default settings
const defaultSettings = [
  ['site_name', 'Arche Vault', 'Application name'],
  ['max_plans_per_user', '10', 'Maximum plans per user'],
  ['min_contribution_amount', '0.001', 'Minimum contribution amount'],
  ['simulation_enabled', 'true', 'Enable automatic contributions'],
  ['registration_enabled', 'true', 'Allow new user registration']
];

defaultSettings.forEach(([key, value, description]) => {
  try {
    db.prepare('INSERT OR IGNORE INTO settings (key, value, description) VALUES (?, ?, ?)')
      .run(key, value, description);
  } catch (e) { /* ignore duplicates */ }
});

// -------- Enhanced Utility Functions ----------
const utils = {
  generateId: () => crypto.randomUUID(),
  
  hashPassword: (password) => bcrypt.hashSync(password, 12),
  
  verifyPassword: (password, hash) => bcrypt.compareSync(password, hash),
  
  issueJWT: (payload, expiresIn = '7d') => {
    return jwt.sign(payload, config.secret, { expiresIn });
  },
  
  verifyJWT: (token) => {
    try { return jwt.verify(token, config.secret); } 
    catch { return null; }
  },
  
  nowISO: () => new Date().toISOString(),
  
  addDays: (days) => new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString(),
  
  formatCurrency: (amount, currency = 'BTC') => {
    const decimals = currency === 'BTC' ? 8 : currency === 'ETH' ? 6 : 2;
    return parseFloat(amount).toFixed(decimals) + ' ' + currency;
  },
  
  calculateNextContribution: (frequency) => {
    const days = frequency === 'daily' ? 1 : frequency === 'weekly' ? 7 : 30;
    return utils.addDays(days);
  },
  
  sanitizeInput: (str) => {
    if (typeof str !== 'string') return str;
    return str.trim().replace(/[<>]/g, '');
  },
  
  logAudit: (userId, action, metadata = {}, req = null) => {
    try {
      const ip = req?.ip || req?.connection?.remoteAddress || 'unknown';
      const userAgent = req?.headers['user-agent'] || 'unknown';
      
      db.prepare(`INSERT INTO audit_logs 
                  (user_id, action, ip_address, user_agent, metadata) 
                  VALUES (?, ?, ?, ?, ?)`).run(
        userId, action, ip, userAgent, JSON.stringify(metadata)
      );
    } catch (e) {
      console.error('Audit log failed:', e.message);
    }
  },
  
  createNotification: (userId, title, message, level = 'info', category = 'general') => {
    try {
      return db.prepare(`INSERT INTO notifications 
                        (user_id, title, message, level, category) 
                        VALUES (?, ?, ?, ?, ?)`).run(userId, title, message, level, category);
    } catch (e) {
      console.error('Notification creation failed:', e.message);
    }
  },
  
  getSetting: (key, defaultValue = null) => {
    try {
      const setting = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
      return setting ? setting.value : defaultValue;
    } catch (e) {
      return defaultValue;
    }
  }
};

// -------- Enhanced Express Setup ----------
const app = express();

// Security middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? ['https://yourdomain.com'] : true,
  credentials: true
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Request logging and rate limiting middleware
app.use((req, res, next) => {
  req.startTime = Date.now();
  console.log(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Authentication middleware
const authMiddleware = (req, res, next) => {
  // Public endpoints
  const publicPaths = [
    '/api/auth/login', '/api/auth/register', '/api/contact', 
    '/_health', '/', '/favicon.ico'
  ];
  
  if (publicPaths.some(path => req.path.startsWith(path))) {
    return next();
  }
  
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }
  
  const token = authHeader.substring(7);
  const payload = utils.verifyJWT(token);
  
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  // Check if user is still active
  const user = db.prepare('SELECT id, is_active, locked_until FROM users WHERE id = ?').get(payload.userId);
  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Account disabled' });
  }
  
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return res.status(423).json({ error: 'Account temporarily locked' });
  }
  
  req.user = payload;
  next();
};

app.use(authMiddleware);

// Admin middleware
const adminMiddleware = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// -------- Enhanced API Routes ----------

// Health check
app.get('/_health', (req, res) => {
  const dbHealth = () => {
    try {
      db.prepare('SELECT 1').get();
      return true;
    } catch { return false; }
  };
  
  res.json({
    status: 'ok',
    timestamp: utils.nowISO(),
    database: dbHealth() ? 'connected' : 'error',
    version: '2.0.0'
  });
});

// Enhanced Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    // Check registration is enabled
    if (utils.getSetting('registration_enabled') !== 'true') {
      return res.status(403).json({ error: 'Registration is currently disabled' });
    }
    
    // Check if username or email exists
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?')
      .get(username, email);
    
    if (existing) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    
    const hashedPassword = utils.hashPassword(password);
    const result = db.prepare(`INSERT INTO users 
                              (username, email, password_hash, display_name) 
                              VALUES (?, ?, ?, ?)`).run(
      utils.sanitizeInput(username),
      email ? utils.sanitizeInput(email) : null,
      hashedPassword,
      displayName ? utils.sanitizeInput(displayName) : username
    );
    
    utils.logAudit(result.lastInsertRowid, 'user.register', { username }, req);
    utils.createNotification(result.lastInsertRowid, 'Welcome!', 
      'Your account has been created successfully. Start by creating your first savings plan.');
    
    res.status(201).json({ 
      success: true, 
      message: 'Account created successfully',
      userId: result.lastInsertRowid 
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = db.prepare(`SELECT id, username, email, password_hash, display_name, 
                            is_admin, is_active, login_attempts, locked_until 
                            FROM users WHERE username = ? OR email = ?`)
      .get(username, username);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check account status
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is disabled' });
    }
    
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Account is temporarily locked' });
    }
    
    if (user.login_attempts >= config.maxLoginAttempts) {
      const lockUntil = new Date(Date.now() + config.lockoutDuration).toISOString();
      db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockUntil, user.id);
      return res.status(423).json({ error: 'Account locked due to too many failed attempts' });
    }
    
    const validPassword = utils.verifyPassword(password, user.password_hash);
    
    if (!validPassword) {
      db.prepare('UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?')
        .run(user.id);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset login attempts and update last login
    db.prepare(`UPDATE users SET login_attempts = 0, locked_until = NULL, 
                last_login = CURRENT_TIMESTAMP WHERE id = ?`).run(user.id);
    
    const token = utils.issueJWT({
      userId: user.id,
      username: user.username,
      isAdmin: !!user.is_admin
    });
    
    // Create session
    const sessionId = utils.generateId();
    db.prepare(`INSERT INTO user_sessions (id, user_id, ip_address, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, ?)`).run(
      sessionId,
      user.id,
      req.ip,
      req.headers['user-agent'] || '',
      utils.addDays(7)
    );
    
    utils.logAudit(user.id, 'user.login', { sessionId }, req);
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.display_name,
        isAdmin: !!user.is_admin
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Enhanced Profile Routes
app.get('/api/profile', (req, res) => {
  try {
    const user = db.prepare(`SELECT id, username, email, display_name, 
                            is_admin, timezone, created_at, last_login 
                            FROM users WHERE id = ?`).get(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const stats = {
      totalPlans: db.prepare('SELECT COUNT(*) as count FROM plans WHERE user_id = ?')
        .get(req.user.userId).count,
      activePlans: db.prepare('SELECT COUNT(*) as count FROM plans WHERE user_id = ? AND status = "active"')
        .get(req.user.userId).count,
      totalSaved: db.prepare('SELECT SUM(progress) as total FROM plans WHERE user_id = ?')
        .get(req.user.userId).total || 0,
      thisMonthContributions: db.prepare(`SELECT SUM(amount) as total FROM contributions 
                                         WHERE user_id = ? AND contributed_at >= date('now', 'start of month')`)
        .get(req.user.userId).total || 0
    };
    
    res.json({ user, stats });
    
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

// Enhanced Plans Routes
app.get('/api/plans', (req, res) => {
  try {
    const { status, type, limit = 50, offset = 0 } = req.query;
    let query = 'SELECT * FROM plans WHERE user_id = ?';
    const params = [req.user.userId];
    
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    
    if (type) {
      query += ' AND plan_type = ?';
      params.push(type);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const plans = db.prepare(query).all(...params);
    
    // Add progress percentages and next contribution info
    const enhancedPlans = plans.map(plan => ({
      ...plan,
      progressPercentage: plan.target_amount ? 
        Math.min(100, (plan.progress / plan.target_amount) * 100) : 
        Math.min(100, (plan.progress / plan.total_contributions) * 100),
      formattedAmount: utils.formatCurrency(plan.amount, plan.currency),
      formattedProgress: utils.formatCurrency(plan.progress, plan.currency),
      daysUntilNext: plan.next_contribution ? 
        Math.ceil((new Date(plan.next_contribution) - new Date()) / (1000 * 60 * 60 * 24)) : null
    }));
    
    res.json(enhancedPlans);
    
  } catch (error) {
    console.error('Plans error:', error);
    res.status(500).json({ error: 'Failed to load plans' });
  }
});

app.post('/api/plans', (req, res) => {
  try {
    const {
      title, description, planType = 'savings', amount, frequency, 
      duration, currency = 'BTC', targetAmount, autoContribute = true,
      priority = 1, tags = []
    } = req.body || {};
    
    if (!title || !amount || !frequency || !duration) {
      return res.status(400).json({ error: 'Title, amount, frequency, and duration are required' });
    }
    
    if (!config.currencies.includes(currency)) {
      return res.status(400).json({ error: 'Invalid currency' });
    }
    
    // Check user plan limit
    const userPlanCount = db.prepare('SELECT COUNT(*) as count FROM plans WHERE user_id = ?')
      .get(req.user.userId).count;
    const maxPlans = parseInt(utils.getSetting('max_plans_per_user', '10'));
    
    if (userPlanCount >= maxPlans) {
      return res.status(400).json({ error: `Maximum ${maxPlans} plans allowed per user` });
    }
    
    const parsedAmount = parseFloat(amount);
    const multiplier = frequency === 'daily' ? 30 : frequency === 'weekly' ? 4 : 1;
    const totalContributions = parsedAmount * multiplier * parseInt(duration);
    const nextContribution = autoContribute ? utils.calculateNextContribution(frequency) : null;
    
    const result = db.prepare(`INSERT INTO plans 
                              (user_id, title, description, plan_type, amount, frequency, 
                               duration, currency, target_amount, auto_contribute, priority, 
                               total_contributions, next_contribution, tags) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      req.user.userId,
      utils.sanitizeInput(title),
      description ? utils.sanitizeInput(description) : null,
      planType,
      parsedAmount,
      frequency,
      parseInt(duration),
      currency,
      targetAmount ? parseFloat(targetAmount) : totalContributions,
      autoContribute ? 1 : 0,
      parseInt(priority),
      totalContributions,
      nextContribution,
      JSON.stringify(tags)
    );
    
    const plan = db.prepare('SELECT * FROM plans WHERE id = ?').get(result.lastInsertRowid);
    
    utils.createNotification(req.user.userId, 'Plan Created', 
      `Your ${planType} plan "${title}" has been created successfully.`, 'success');
    
    utils.logAudit(req.user.userId, 'plan.create', { planId: plan.id, title }, req);
    
    res.status(201).json(plan);
    
  } catch (error) {
    console.error('Plan creation error:', error);
    res.status(500).json({ error: 'Failed to create plan' });
  }
});

// Enhanced Contribution Routes
app.post('/api/contribute', (req, res) => {
  try {
    const { planId, amount, note, paymentMethod = 'manual' } = req.body || {};
    
    if (!planId || !amount) {
      return res.status(400).json({ error: 'Plan ID and amount are required' });
    }
    
    const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND user_id = ?')
      .get(planId, req.user.userId);
    
    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }
    
    if (plan.status !== 'active') {
      return res.status(400).json({ error: 'Cannot contribute to inactive plan' });
    }
    
    const contributionAmount = parseFloat(amount);
    const minAmount = parseFloat(utils.getSetting('min_contribution_amount', '0.001'));
    
    if (contributionAmount < minAmount) {
      return res.status(400).json({ 
        error: `Minimum contribution amount is ${utils.formatCurrency(minAmount, plan.currency)}` 
      });
    }
    
    // Begin transaction
    const contribution = db.transaction(() => {
      const result = db.prepare(`INSERT INTO contributions 
                                (plan_id, user_id, amount, payment_method, note) 
                                VALUES (?, ?, ?, ?, ?)`).run(
        planId, req.user.userId, contributionAmount, paymentMethod, note || ''
      );
      
      const newProgress = (plan.progress || 0) + contributionAmount;
      const nextContribution = plan.auto_contribute ? 
        utils.calculateNextContribution(plan.frequency) : plan.next_contribution;
      
      db.prepare('UPDATE plans SET progress = ?, next_contribution = ? WHERE id = ?')
        .run(newProgress, nextContribution, planId);
      
      // Check if goal is reached
      if (plan.target_amount && newProgress >= plan.target_amount) {
        db.prepare('UPDATE plans SET status = ?, completion_date = CURRENT_TIMESTAMP WHERE id = ?')
          .run('completed', planId);
        
        utils.createNotification(req.user.userId, 'Goal Achieved! 🎉', 
          `Congratulations! You've reached your goal for "${plan.title}".`, 'success');
      }
      
      return db.prepare('SELECT * FROM contributions WHERE id = ?').get(result.lastInsertRowid);
    })();
    
    utils.createNotification(req.user.userId, 'Contribution Recorded', 
      `${utils.formatCurrency(contributionAmount, plan.currency)} added to "${plan.title}".`);
    
    utils.logAudit(req.user.userId, 'contribution.add', 
      { planId, amount: contributionAmount, method: paymentMethod }, req);
    
    res.status(201).json(contribution);
    
  } catch (error) {
    console.error('Contribution error:', error);
    res.status(500).json({ error: 'Failed to process contribution' });
  }
});

// Enhanced Admin Routes
app.get('/api/admin/dashboard', adminMiddleware, (req, res) => {
  try {
    const stats = {
      users: {
        total: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
        active: db.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1').get().count,
        admins: db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 1').get().count,
        newThisMonth: db.prepare(`SELECT COUNT(*) as count FROM users 
                                 WHERE created_at >= date('now', 'start of month')`).get().count
      },
      plans: {
        total: db.prepare('SELECT COUNT(*) as count FROM plans').get().count,
        active: db.prepare('SELECT COUNT(*) as count FROM plans WHERE status = "active"').get().count,
        completed: db.prepare('SELECT COUNT(*) as count FROM plans WHERE status = "completed"').get().count,
        totalValue: db.prepare('SELECT SUM(progress) as total FROM plans').get().total || 0
      },
      contributions: {
        total: db.prepare('SELECT COUNT(*) as count FROM contributions').get().count,
        thisMonth: db.prepare(`SELECT COUNT(*) as count FROM contributions 
                              WHERE contributed_at >= date('now', 'start of month')`).get().count,
        totalAmount: db.prepare('SELECT SUM(amount) as total FROM contributions').get().total || 0
      },
              system: {
        dbSize: fs.statSync(config.dbPath).size,
        uptime: process.uptime(),
        version: '2.0.0'
      }
    };
    
    // Recent activity
    const recentUsers = db.prepare(`SELECT id, username, display_name, created_at 
                                   FROM users ORDER BY created_at DESC LIMIT 10`).all();
    const recentContributions = db.prepare(`SELECT c.*, p.title as plan_title, u.username 
                                           FROM contributions c 
                                           JOIN plans p ON c.plan_id = p.id 
                                           JOIN users u ON c.user_id = u.id 
                                           ORDER BY c.contributed_at DESC LIMIT 20`).all();
    
    res.json({ stats, recentUsers, recentContributions });
    
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

app.get('/api/admin/users', adminMiddleware, (req, res) => {
  try {
    const { search, status, limit = 50, offset = 0 } = req.query;
    let query = `SELECT id, username, email, display_name, is_admin, is_active, 
                 login_attempts, created_at, last_login FROM users`;
    const params = [];
    const conditions = [];
    
    if (search) {
      conditions.push('(username LIKE ? OR email LIKE ? OR display_name LIKE ?)');
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }
    
    if (status === 'active') {
      conditions.push('is_active = 1');
    } else if (status === 'inactive') {
      conditions.push('is_active = 0');
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const users = db.prepare(query).all(...params);
    const total = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    
    res.json({ users, total });
    
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// Enhanced Notifications
app.get('/api/notifications', (req, res) => {
  try {
    const { unreadOnly, limit = 50, offset = 0 } = req.query;
    let query = `SELECT id, title, message, level, category, read, 
                 action_url, created_at FROM notifications WHERE user_id = ?`;
    const params = [req.user.userId];
    
    if (unreadOnly === 'true') {
      query += ' AND read = 0';
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    const notifications = db.prepare(query).all(...params);
    const unreadCount = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND read = 0')
      .get(req.user.userId).count;
    
    res.json({ notifications, unreadCount });
    
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ error: 'Failed to load notifications' });
  }
});

// Simulation Engine
function simulationEngine() {
  try {
    if (utils.getSetting('simulation_enabled') !== 'true') {
      return;
    }
    
    const now = new Date().toISOString();
    const duePlans = db.prepare(`SELECT * FROM plans 
                                WHERE status = 'active' 
                                AND auto_contribute = 1 
                                AND next_contribution <= ?`).all(now);
    
    console.log(`🔄 Processing ${duePlans.length} due contributions...`);
    
    duePlans.forEach(plan => {
      try {
        const transaction = db.transaction(() => {
          // Create contribution
          const result = db.prepare(`INSERT INTO contributions 
                                    (plan_id, user_id, amount, transaction_type, payment_method, note) 
                                    VALUES (?, ?, ?, 'deposit', 'auto', 'Automated scheduled contribution')`).run(
            plan.id, plan.user_id, plan.amount
          );
          
          // Update plan progress
          const newProgress = (plan.progress || 0) + parseFloat(plan.amount);
          const nextContribution = utils.calculateNextContribution(plan.frequency);
          
          db.prepare('UPDATE plans SET progress = ?, next_contribution = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
            .run(newProgress, nextContribution, plan.id);
          
          // Check completion
          if (plan.target_amount && newProgress >= plan.target_amount) {
            db.prepare('UPDATE plans SET status = ?, completion_date = CURRENT_TIMESTAMP WHERE id = ?')
              .run('completed', plan.id);
            
            utils.createNotification(plan.user_id, 'Goal Achieved! 🎉', 
              `Congratulations! You've completed your "${plan.title}" savings plan.`, 'success');
          } else {
            utils.createNotification(plan.user_id, 'Contribution Processed', 
              `${utils.formatCurrency(plan.amount, plan.currency)} automatically added to "${plan.title}".`);
          }
          
          utils.logAudit(plan.user_id, 'contribution.auto', {
            planId: plan.id,
            amount: plan.amount,
            nextContribution
          });
          
          return result.lastInsertRowid;
        });
        
        transaction();
        
      } catch (error) {
        console.error(`Failed to process contribution for plan ${plan.id}:`, error);
      }
    });
    
    if (duePlans.length > 0) {
      console.log(`✅ Processed ${duePlans.length} automatic contributions`);
    }
    
  } catch (error) {
    console.error('Simulation engine error:', error);
  }
}

// Start simulation
setInterval(simulationEngine, config.simulationInterval);
setTimeout(simulationEngine, 5000); // Initial run after 5 seconds

// Enhanced Frontend
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Arche Vault - Advanced Savings Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover { transition: all 0.3s ease; }
        .card-hover:hover { transform: translateY(-5px); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1); }
        .toast { position: fixed; top: 20px; right: 20px; z-index: 9999; }
        .notification-badge { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
        .progress-bar { transition: width 0.5s ease-in-out; }
        .modal-backdrop { backdrop-filter: blur(4px); }
    </style>
</head>
<body class="bg-gray-50" x-data="app()" x-init="init()">

<!-- Navigation -->
<nav class="bg-white shadow-lg sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between items-center py-4">
            <div class="flex items-center space-x-4">
                <div class="text-2xl font-bold gradient-bg bg-clip-text text-transparent">
                    <i class="fas fa-vault mr-2"></i>Arche Vault
                </div>
                <div class="hidden md:flex items-center text-sm text-gray-600">
                    <span class="bg-green-100 text-green-800 px-2 py-1 rounded-full">v2.0.0</span>
                </div>
            </div>
            
            <div class="flex items-center space-x-4">
                <!-- Guest buttons -->
                <div x-show="!isAuthenticated" class="flex items-center space-x-2">
                    <button @click="showLoginModal = true" 
                            class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
                        Login
                    </button>
                    <button @click="showRegisterModal = true" 
                            class="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition">
                        Register
                    </button>
                </div>
                
                <!-- Authenticated user menu -->
                <div x-show="isAuthenticated" class="flex items-center space-x-4">
                    <!-- Notifications -->
                    <div class="relative">
                        <button @click="toggleNotifications()" 
                                class="p-2 text-gray-600 hover:text-gray-900 relative">
                            <i class="fas fa-bell text-xl"></i>
                            <span x-show="unreadCount > 0" 
                                  x-text="unreadCount"
                                  class="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center notification-badge">
                            </span>
                        </button>
                        
                        <!-- Notifications dropdown -->
                        <div x-show="showNotifications" 
                             @click.away="showNotifications = false"
                             x-transition
                             class="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg border max-h-96 overflow-y-auto z-50">
                            <div class="p-4 border-b">
                                <h3 class="font-semibold">Notifications</h3>
                            </div>
                            <div class="max-h-64 overflow-y-auto">
                                <template x-for="notification in notifications" :key="notification.id">
                                    <div class="p-3 border-b hover:bg-gray-50 cursor-pointer"
                                         :class="{'bg-blue-50': !notification.read}">
                                        <div class="font-medium text-sm" x-text="notification.title"></div>
                                        <div class="text-xs text-gray-600 mt-1" x-text="notification.message"></div>
                                        <div class="text-xs text-gray-400 mt-1" x-text="formatDate(notification.created_at)"></div>
                                    </div>
                                </template>
                                <div x-show="notifications.length === 0" class="p-4 text-center text-gray-500">
                                    No notifications
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- User menu -->
                    <div class="relative" x-data="{ open: false }">
                        <button @click="open = !open" 
                                class="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-100 transition">
                            <div class="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white font-semibold">
                                <span x-text="user.username ? user.username.charAt(0).toUpperCase() : 'U'"></span>
                            </div>
                            <span class="font-medium" x-text="user.displayName || user.username"></span>
                            <i class="fas fa-chevron-down text-sm"></i>
                        </button>
                        
                        <div x-show="open" @click.away="open = false" x-transition
                             class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border z-50">
                            <div class="p-2">
                                <button @click="showProfileModal = true; open = false" 
                                        class="w-full text-left px-3 py-2 rounded hover:bg-gray-100 transition">
                                    <i class="fas fa-user mr-2"></i>Profile
                                </button>
                                <button x-show="user.isAdmin" @click="showAdminPanel = !showAdminPanel; open = false"
                                        class="w-full text-left px-3 py-2 rounded hover:bg-gray-100 transition">
                                    <i class="fas fa-cog mr-2"></i>Admin Panel
                                </button>
                                <hr class="my-2">
                                <button @click="logout(); open = false" 
                                        class="w-full text-left px-3 py-2 rounded hover:bg-red-50 text-red-600 transition">
                                    <i class="fas fa-sign-out-alt mr-2"></i>Logout
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</nav>

<!-- Hero Section -->
<section class="gradient-bg py-16 text-white">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid md:grid-cols-2 gap-12 items-center">
            <div>
                <h1 class="text-5xl font-bold mb-6">Smart Crypto Savings Platform</h1>
                <p class="text-xl mb-8 opacity-90">
                    Automate your savings with intelligent plans, real-time analytics, 
                    and secure cryptocurrency management.
                </p>
                <div class="flex space-x-4">
                    <button x-show="!isAuthenticated" @click="showRegisterModal = true"
                            class="px-8 py-3 bg-white text-blue-600 rounded-lg font-semibold hover:bg-gray-100 transition">
                        Get Started
                    </button>
                    <button x-show="isAuthenticated" @click="showCreatePlanModal = true"
                            class="px-8 py-3 bg-white text-blue-600 rounded-lg font-semibold hover:bg-gray-100 transition">
                        Create New Plan
                    </button>
                    <button class="px-8 py-3 border border-white text-white rounded-lg font-semibold hover:bg-white hover:text-blue-600 transition">
                        Learn More
                    </button>
                </div>
            </div>
            <div class="hidden md:block">
                <div class="bg-white bg-opacity-10 backdrop-blur-sm rounded-2xl p-6">
                    <canvas id="heroChart" class="w-full h-64"></canvas>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Stats Section -->
<section x-show="isAuthenticated" class="py-8 bg-white shadow-sm">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div class="text-center">
                <div class="text-3xl font-bold text-blue-600" x-text="formatCurrency(stats.totalSaved)"></div>
                <div class="text-sm text-gray-600">Total Saved</div>
            </div>
            <div class="text-center">
                <div class="text-3xl font-bold text-green-600" x-text="stats.activePlans"></div>
                <div class="text-sm text-gray-600">Active Plans</div>
            </div>
            <div class="text-center">
                <div class="text-3xl font-bold text-purple-600" x-text="formatCurrency(stats.thisMonthContributions)"></div>
                <div class="text-sm text-gray-600">This Month</div>
            </div>
            <div class="text-center">
                <div class="text-3xl font-bold text-orange-600" x-text="stats.totalPlans"></div>
                <div class="text-sm text-gray-600">Total Plans</div>
            </div>
        </div>
    </div>
</section>

<!-- Main Dashboard -->
<main x-show="isAuthenticated" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <div class="grid lg:grid-cols-3 gap-8">
        <!-- Left Column - Plans & Charts -->
        <div class="lg:col-span-2 space-y-8">
            
            <!-- Quick Actions -->
            <div class="bg-white rounded-xl shadow-sm p-6">
                <div class="flex items-center justify-between mb-6">
                    <h2 class="text-xl font-semibold">Quick Actions</h2>
                    <button @click="refreshData()" 
                            class="p-2 text-gray-500 hover:text-gray-700 rounded-lg hover:bg-gray-100">
                        <i class="fas fa-refresh"></i>
                    </button>
                </div>
                <div class="grid md:grid-cols-3 gap-4">
                    <button @click="showCreatePlanModal = true"
                            class="p-4 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 transition card-hover">
                        <i class="fas fa-plus text-2xl mb-2"></i>
                        <div class="font-semibold">Create Plan</div>
                    </button>
                    <button @click="showContributeModal = true"
                            class="p-4 bg-green-50 text-green-600 rounded-lg hover:bg-green-100 transition card-hover">
                        <i class="fas fa-coins text-2xl mb-2"></i>
                        <div class="font-semibold">Add Funds</div>
                    </button>
                    <button @click="showAnalyticsModal = true"
                            class="p-4 bg-purple-50 text-purple-600 rounded-lg hover:bg-purple-100 transition card-hover">
                        <i class="fas fa-chart-bar text-2xl mb-2"></i>
                        <div class="font-semibold">Analytics</div>
                    </button>
                </div>
            </div>
            
            <!-- Charts -->
            <div class="bg-white rounded-xl shadow-sm p-6">
                <div class="flex items-center justify-between mb-6">
                    <h2 class="text-xl font-semibold">Portfolio Overview</h2>
                    <select x-model="chartTimeframe" @change="loadCharts()"
                            class="border rounded-lg px-3 py-1 text-sm">
                        <option value="7d">Last 7 days</option>
                        <option value="30d">Last 30 days</option>
                        <option value="90d">Last 90 days</option>
                        <option value="1y">Last year</option>
                    </select>
                </div>
                <canvas id="portfolioChart" class="w-full h-64"></canvas>
            </div>
            
            <!-- Plans List -->
            <div class="bg-white rounded-xl shadow-sm">
                <div class="p-6 border-b">
                    <div class="flex items-center justify-between">
                        <h2 class="text-xl font-semibold">My Savings Plans</h2>
                        <div class="flex space-x-2">
                            <select x-model="planFilter" @change="filterPlans()"
                                    class="border rounded-lg px-3 py-1 text-sm">
                                <option value="all">All Plans</option>
                                <option value="active">Active</option>
                                <option value="completed">Completed</option>
                                <option value="paused">Paused</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="p-6">
                    <div class="space-y-4">
                        <template x-for="plan in filteredPlans" :key="plan.id">
                            <div class="border rounded-lg p-6 card-hover">
                                <div class="flex items-start justify-between mb-4">
                                    <div class="flex-1">
                                        <div class="flex items-center space-x-3 mb-2">
                                            <h3 class="font-semibold text-lg" x-text="plan.title"></h3>
                                            <span class="px-2 py-1 rounded-full text-xs font-medium"
                                                  :class="{
                                                    'bg-green-100 text-green-800': plan.status === 'active',
                                                    'bg-blue-100 text-blue-800': plan.status === 'completed',
                                                    'bg-yellow-100 text-yellow-800': plan.status === 'paused'
                                                  }"
                                                  x-text="plan.status.toUpperCase()">
                                            </span>
                                        </div>
                                        <p class="text-gray-600 text-sm mb-3" x-text="plan.description"></p>
                                        <div class="grid md:grid-cols-3 gap-4 text-sm">
                                            <div>
                                                <span class="text-gray-500">Amount:</span>
                                                <span class="font-medium ml-1" x-text="formatCurrency(plan.amount, plan.currency)"></span>
                                            </div>
                                            <div>
                                                <span class="text-gray-500">Frequency:</span>
                                                <span class="font-medium ml-1 capitalize" x-text="plan.frequency"></span>
                                            </div>
                                            <div>
                                                <span class="text-gray-500">Progress:</span>
                                                <span class="font-medium ml-1" x-text="Math.round(plan.progressPercentage) + '%'"></span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <button @click="quickContribute(plan)" 
                                                x-show="plan.status === 'active'"
                                                class="px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700 transition">
                                            <i class="fas fa-plus mr-1"></i>Add
                                        </button>
                                        <button @click="togglePlan(plan)" 
                                                class="px-3 py-1 border rounded text-sm hover:bg-gray-50 transition">
                                            <i class="fas" :class="plan.status === 'active' ? 'fa-pause' : 'fa-play'"></i>
                                            <span x-text="plan.status === 'active' ? 'Pause' : 'Resume'"></span>
                                        </button>
                                    </div>
                                </div>
                                
                                <!-- Progress bar -->
                                <div class="mb-4">
                                    <div class="flex justify-between text-sm text-gray-600 mb-2">
                                        <span x-text="formatCurrency(plan.progress, plan.currency)"></span>
                                        <span x-text="formatCurrency(plan.target_amount || plan.total_contributions, plan.currency)"></span>
                                    </div>
                                    <div class="w-full bg-gray-200 rounded-full h-2">
                                        <div class="h-2 rounded-full progress-bar"
                                             :style="'width: ' + Math.min(100, plan.progressPercentage) + '%'"
                                             :class="{
                                               'bg-gradient-to-r from-green-400 to-blue-500': plan.progressPercentage < 100,
                                               'bg-gradient-to-r from-green-500 to-green-600': plan.progressPercentage >= 100
                                             }">
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Next contribution -->
                                <div x-show="plan.next_contribution && plan.status === 'active'" 
                                     class="text-xs text-gray-500">
                                    Next contribution: <span x-text="formatDate(plan.next_contribution)"></span>
                                </div>
                            </div>
                        </template>
                        
                        <div x-show="filteredPlans.length === 0" 
                             class="text-center py-12 text-gray-500">
                            <i class="fas fa-piggy-bank text-4xl mb-4"></i>
                            <p class="text-lg mb-2">No savings plans yet</p>
                            <button @click="showCreatePlanModal = true"
                                    class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
                                Create Your First Plan
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Right Column - Sidebar -->
        <div class="space-y-6">
            <!-- Profile Card -->
            <div class="bg-white rounded-xl shadow-sm p-6">
                <div class="text-center mb-6">
                    <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white text-2xl font-bold mx-auto mb-4">
                        <span x-text="user.username ? user.username.charAt(0).toUpperCase() : 'U'"></span>
                    </div>
                    <h3 class="font-semibold text-lg" x-text="user.displayName || user.username"></h3>
                    <p class="text-gray-500 text-sm" x-text="user.email"></p>
                </div>
                <div class="space-y-3 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-500">Total Saved</span>
                        <span class="font-medium" x-text="formatCurrency(stats.totalSaved)"></span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-500">Active Plans</span>
                        <span class="font-medium" x-text="stats.activePlans"></span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-500">Member Since</span>
                        <span class="font-medium" x-text="formatDate(user.created_at)"></span>
                    </div>
                </div>
                <button @click="showProfileModal = true"
                        class="w-full mt-4 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition">
                    Edit Profile
                </button>
            </div>
            
            <!-- Recent Transactions -->
            <div class="bg-white rounded-xl shadow-sm p-6">
                <h3 class="font-semibold mb-4">Recent Activity</h3>
                <div class="space-y-3">
                    <template x-for="tx in recentTransactions" :key="tx.id">
                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div class="flex items-center space-x-3">
                                <div class="w-8 h-8 bg-green-100 text-green-600 rounded-full flex items-center justify-center">
                                    <i class="fas fa-plus text-sm"></i>
                                </div>
                                <div>
                                    <div class="font-medium text-sm">Plan #<span x-text="tx.plan_id"></span></div>
                                    <div class="text-xs text-gray-500" x-text="formatDate(tx.contributed_at)"></div>
                                </div>
                            </div>
                            <div class="font-medium text-sm text-green-600">
                                +<span x-text="formatCurrency(tx.amount)"></span>
                            </div>
                        </div>
                    </template>
                    <div x-show="recentTransactions.length === 0" 
                         class="text-center py-4 text-gray-500 text-sm">
                        No recent transactions
                    </div>
                </div>
            </div>
            
            <!-- Admin Panel -->
            <div x-show="user.isAdmin && showAdminPanel" class="bg-white rounded-xl shadow-sm p-6">
                <h3 class="font-semibold mb-4">Admin Panel</h3>
                <div class="space-y-3">
                    <button @click="showAdminDashboard = true"
                            class="w-full px-4 py-2 text-left bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 transition">
                        <i class="fas fa-chart-line mr-2"></i>Dashboard
                    </button>
                    <button @click="exportData('users')"
                            class="w-full px-4 py-2 text-left bg-green-50 text-green-600 rounded-lg hover:bg-green-100 transition">
                        <i class="fas fa-download mr-2"></i>Export Users
                    </button>
                    <button @click="exportData('transactions')"
                            class="w-full px-4 py-2 text-left bg-purple-50 text-purple-600 rounded-lg hover:bg-purple-100 transition">
                        <i class="fas fa-file-export mr-2"></i>Export Transactions
                    </button>
                    <button @click="forceSimulation()"
                            class="w-full px-4 py-2 text-left bg-yellow-50 text-yellow-600 rounded-lg hover:bg-yellow-100 transition">
                        <i class="fas fa-play mr-2"></i>Force Simulation
                    </button>
                </div>
            </div>
        </div>
    </div>
</main>

<!-- Guest Landing Content -->
<main x-show="!isAuthenticated" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
    <div class="grid lg:grid-cols-3 gap-12">
        <!-- Features -->
        <div class="lg:col-span-2">
            <h2 class="text-3xl font-bold mb-8">Why Choose Arche Vault?</h2>
            <div class="grid md:grid-cols-2 gap-8">
                <div class="card-hover p-6 border rounded-xl">
                    <div class="w-12 h-12 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center mb-4">
                        <i class="fas fa-robot text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-lg mb-3">Automated Savings</h3>
                    <p class="text-gray-600">Set it and forget it. Our smart system automatically manages your contributions based on your schedule.</p>
                </div>
                
                <div class="card-hover p-6 border rounded-xl">
                    <div class="w-12 h-12 bg-green-100 text-green-600 rounded-lg flex items-center justify-center mb-4">
                        <i class="fas fa-shield-alt text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-lg mb-3">Secure & Private</h3>
                    <p class="text-gray-600">Bank-level security with encrypted data storage and secure authentication protocols.</p>
                </div>
                
                <div class="card-hover p-6 border rounded-xl">
                    <div class="w-12 h-12 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center mb-4">
                        <i class="fas fa-chart-bar text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-lg mb-3">Advanced Analytics</h3>
                    <p class="text-gray-600">Track your progress with detailed charts, insights, and personalized recommendations.</p>
                </div>
                
                <div class="card-hover p-6 border rounded-xl">
                    <div class="w-12 h-12 bg-orange-100 text-orange-600 rounded-lg flex items-center justify-center mb-4">
                        <i class="fas fa-coins text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-lg mb-3">Multi-Currency Support</h3>
                    <p class="text-gray-600">Support for Bitcoin, Ethereum, USD, EUR and more cryptocurrencies and fiat currencies.</p>
                </div>
            </div>
        </div>
        
        <!-- Contact Form -->
        <div class="bg-white p-8 rounded-xl shadow-lg">
            <h3 class="text-xl font-semibold mb-6">Get In Touch</h3>
            <form @submit.prevent="submitContact()">
                <div class="space-y-4">
                    <input x-model="contactForm.name" 
                           type="text" placeholder="Your Name" required
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <input x-model="contactForm.email" 
                           type="email" placeholder="Your Email" required
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <input x-model="contactForm.subject" 
                           type="text" placeholder="Subject"
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <textarea x-model="contactForm.message" 
                              placeholder="Your Message" rows="4" required
                              class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"></textarea>
                    <button type="submit" :disabled="contactSubmitting"
                            class="w-full py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:opacity-50">
                        <span x-show="!contactSubmitting">Send Message</span>
                        <span x-show="contactSubmitting">Sending...</span>
                    </button>
                </div>
            </form>
        </div>
    </div>
</main>

<!-- Modals -->
<!-- Login Modal -->
<div x-show="showLoginModal" 
     x-transition:enter="transition ease-out duration-300"
     x-transition:enter-start="opacity-0"
     x-transition:enter-end="opacity-100"
     class="fixed inset-0 bg-black bg-opacity-50 modal-backdrop flex items-center justify-center z-50">
    <div @click.away="showLoginModal = false" 
         class="bg-white rounded-xl p-8 max-w-md w-full mx-4">
        <h3 class="text-2xl font-bold mb-6">Welcome Back</h3>
        <form @submit.prevent="login()">
            <div class="space-y-4">
                <input x-model="loginForm.username" 
                       type="text" placeholder="Username or Email" required
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <input x-model="loginForm.password" 
                       type="password" placeholder="Password" required
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <button type="submit" :disabled="loginSubmitting"
                        class="w-full py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:opacity-50">
                    <span x-show="!loginSubmitting">Login</span>
                    <span x-show="loginSubmitting">Logging in...</span>
                </button>
            </div>
        </form>
        <div class="mt-4 text-center">
            <button @click="showLoginModal = false; showRegisterModal = true"
                    class="text-blue-600 hover:text-blue-700">
                Don't have an account? Register
            </button>
        </div>
    </div>
</div>

<!-- Register Modal -->
<div x-show="showRegisterModal" 
     x-transition:enter="transition ease-out duration-300"
     x-transition:enter-start="opacity-0"
     x-transition:enter-end="opacity-100"
     class="fixed inset-0 bg-black bg-opacity-50 modal-backdrop flex items-center justify-center z-50">
    <div @click.away="showRegisterModal = false" 
         class="bg-white rounded-xl p-8 max-w-md w-full mx-4">
        <h3 class="text-2xl font-bold mb-6">Create Account</h3>
        <form @submit.prevent="register()">
            <div class="space-y-4">
                <input x-model="registerForm.username" 
                       type="text" placeholder="Username" required
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <input x-model="registerForm.email" 
                       type="email" placeholder="Email"
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <input x-model="registerForm.displayName" 
                       type="text" placeholder="Display Name"
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <input x-model="registerForm.password" 
                       type="password" placeholder="Password (min 8 characters)" required minlength="8"
                       class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                <button type="submit" :disabled="registerSubmitting"
                        class="w-full py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition disabled:opacity-50">
                    <span x-show="!registerSubmitting">Create Account</span>
                    <span x-show="registerSubmitting">Creating...</span>
                </button>
            </div>
        </form>
        <div class="mt-4 text-center">
            <button @click="showRegisterModal = false; showLoginModal = true"
                    class="text-blue-600 hover:text-blue-700">
                Already have an account? Login
            </button>
        </div>
    </div>
</div>

<!-- Create Plan Modal -->
<div x-show="showCreatePlanModal" 
     x-transition:enter="transition ease-out duration-300"
     x-transition:enter-start="opacity-0"
     x-transition:enter-end="opacity-100"
     class="fixed inset-0 bg-black bg-opacity-50 modal-backdrop flex items-center justify-center z-50">
    <div @click.away="showCreatePlanModal = false" 
         class="bg-white rounded-xl p-8 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <h3 class="text-2xl font-bold mb-6">Create New Savings Plan</h3>
        <form @submit.prevent="createPlan()">
            <div class="grid md:grid-cols-2 gap-6">
                <div class="md:col-span-2">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Plan Title</label>
                    <input x-model="createPlanForm.title" 
                           type="text" placeholder="Emergency Fund" required
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div class="md:col-span-2">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                    <textarea x-model="createPlanForm.description" 
                              placeholder="Describe your savings goal..." rows="3"
                              class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"></textarea>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Plan Type</label>
                    <select x-model="createPlanForm.planType" 
                            class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <option value="savings">Savings</option>
                        <option value="emergency">Emergency Fund</option>
                        <option value="retirement">Retirement</option>
                        <option value="investment">Investment</option>
                    </select>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Currency</label>
                    <select x-model="createPlanForm.currency" 
                            class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <option value="BTC">Bitcoin (BTC)</option>
                        <option value="ETH">Ethereum (ETH)</option>
                        <option value="USD">US Dollar (USD)</option>
                        <option value="EUR">Euro (EUR)</option>
                    </select>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Contribution Amount</label>
                    <input x-model="createPlanForm.amount" 
                           type="number" step="0.00000001" placeholder="0.001" required
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Frequency</label>
                    <select x-model="createPlanForm.frequency" 
                            class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                    </select>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Duration (months)</label>
                    <input x-model="createPlanForm.duration" 
                           type="number" min="1" max="120" placeholder="12" required
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Target Amount (optional)</label>
                    <input x-model="createPlanForm.targetAmount" 
                           type="number" step="0.00000001" placeholder="Auto-calculated"
                           class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div class="md:col-span-2">
                    <div class="flex items-center space-x-3">
                        <input x-model="createPlanForm.autoContribute" 
                               type="checkbox" id="autoContribute"
                               class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
                        <label for="autoContribute" class="text-sm font-medium text-gray-700">
                            Enable automatic contributions
                        </label>
                    </div>
                </div>
            </div>
            
            <div class="flex justify-end space-x-4 mt-6">
                <button type="button" @click="showCreatePlanModal = false"
                        class="px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition">
                    Cancel
                </button>
                <button type="submit" :disabled="createPlanSubmitting"
                        class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition disabled:opacity-50">
                    <span x-show="!createPlanSubmitting">Create Plan</span>
                    <span x-show="createPlanSubmitting">Creating...</span>
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Toast Notifications -->
<div id="toast-container" class="toast space-y-2">
    <template x-for="toast in toasts" :key="toast.id">
        <div class="bg-white border-l-4 rounded-lg shadow-lg p-4 max-w-sm"
             :class="{
               'border-blue-500': toast.type === 'info',
               'border-green-500': toast.type === 'success',
               'border-yellow-500': toast.type === 'warning',
               'border-red-500': toast.type === 'error'
             }"
             x-transition:enter="transform ease-out duration-300 transition"
             x-transition:enter-start="translate-x-full opacity-0"
             x-transition:enter-end="translate-x-0 opacity-100"
             x-transition:leave="transition ease-in duration-300"
             x-transition:leave-start="opacity-100"
             x-transition:leave-end="opacity-0">
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <i class="fas"
                       :class="{
                         'fa-info-circle text-blue-500': toast.type === 'info',
                         'fa-check-circle text-green-500': toast.type === 'success',
                         'fa-exclamation-triangle text-yellow-500': toast.type === 'warning',
                         'fa-times-circle text-red-500': toast.type === 'error'
                       }"></i>
                </div>
                <div class="ml-3 flex-1">
                    <p class="text-sm font-medium text-gray-900" x-text="toast.title"></p>
                    <p x-show="toast.message" class="text-sm text-gray-600 mt-1" x-text="toast.message"></p>
                </div>
                <button @click="removeToast(toast.id)" 
                        class="ml-4 text-gray-400 hover:text-gray-600">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        </div>
    </template>
</div>

<!-- JavaScript -->
<script>
function app() {
    return {
        // State
        isAuthenticated: false,
        user: {},
        token: localStorage.getItem('arche_token'),
        
        // UI State
        showLoginModal: false,
        showRegisterModal: false,
        showCreatePlanModal: false,
        showProfileModal: false,
        showNotifications: false,
        showAdminPanel: false,
        showAdminDashboard: false,
        
        // Data
        plans: [],
        filteredPlans: [],
        notifications: [],
        recentTransactions: [],
        stats: {
            totalSaved: 0,
            activePlans: 0,
            totalPlans: 0,
            thisMonthContributions: 0
        },
        
        // Forms
        loginForm: { username: '', password: '' },
        registerForm: { username: '', email: '', displayName: '', password: '' },
        createPlanForm: {
            title: '',
            description: '',
            planType: 'savings',
            amount: '',
            frequency: 'weekly',
            duration: 12,
            currency: 'BTC',
            targetAmount: '',
            autoContribute: true
        },
        contactForm: { name: '', email: '', subject: '', message: '' },
        
        // Loading states
        loginSubmitting: false,
        registerSubmitting: false,
        createPlanSubmitting: false,
        contactSubmitting: false,
        
        // Filters and pagination
        planFilter: 'all',
        chartTimeframe: '30d',
        
        // Charts
        heroChart: null,
        portfolioChart: null,
        
        // Notifications
        toasts: [],
        unreadCount: 0,
        
        // Initialize
        init() {
            if (this.token) {
                this.verifyToken();
            }
            this.initCharts();
            this.startPeriodicRefresh();
        },
        
        // API Methods
        async api(endpoint, options = {}) {
            const config = {
                headers: {
                    'Content-Type': 'application/json',
                    ...(this.token && { 'Authorization': `Bearer ${this.token}` })
                },
                ...options
            };
            
            if (options.body && typeof options.body === 'object') {
                config.body = JSON.stringify(options.body);
            }
            
            try {
                const response = await fetch(endpoint, config);
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.error || 'Request failed');
                }
                
                return data;
            } catch (error) {
                console.error('API Error:', error);
                this.showToast('Error', error.message, 'error');
                throw error;
            }
        },
        
        // Authentication
        async verifyToken() {
            try {
                const profile = await this.api('/api/profile');
                this.user = profile.user;
                this.stats = profile.stats;
                this.isAuthenticated = true;
                await this.loadDashboardData();
            } catch (error) {
                this.logout();
            }
        },
        
        async login() {
            this.loginSubmitting = true;
            try {
                const response = await this.api('/api/auth/login', {
                    method: 'POST',
                    body: this.loginForm
                });
                
                this.token = response.token;
                this.user = response.user;
                this.isAuthenticated = true;
                
                localStorage.setItem('arche_token', this.token);
                
                this.showLoginModal = false;
                this.loginForm = { username: '', password: '' };
                
                this.showToast('Welcome!', `Hello ${this.user.displayName || this.user.username}`, 'success');
                
                await this.loadDashboardData();
            } catch (error) {
                // Error handled in api method
            } finally {
                this.loginSubmitting = false;
            }
        },
        
        async register() {
            this.registerSubmitting = true;
            try {
                await this.api('/api/auth/register', {
                    method: 'POST',
                    body: this.registerForm
                });
                
                this.showRegisterModal = false;
                this.registerForm = { username: '', email: '', displayName: '', password: '' };
                
                this.showToast('Success!', 'Account created successfully. Please login.', 'success');
                this.showLoginModal = true;
            } catch (error) {
                // Error handled in api method
            } finally {
                this.registerSubmitting = false;
            }
        },
        
        logout() {
            this.isAuthenticated = false;
            this.user = {};
            this.token = null;
            this.plans = [];
            this.notifications = [];
            this.recentTransactions = [];
            
            localStorage.removeItem('arche_token');
            
            this.showToast('Logged out', 'See you later!', 'info');
        },
        
        // Data Loading
        async loadDashboardData() {
            try {
                const [plansData, notificationsData, transactionsData] = await Promise.all([
                    this.api('/api/plans'),
                    this.api('/api/notifications?limit=10'),
                    this.api('/api/transactions?limit=10')
                ]);
                
                this.plans = plansData;
                this.filterPlans();
                
                this.notifications = notificationsData.notifications || [];
                this.unreadCount = notificationsData.unreadCount || 0;
                
                this.recentTransactions = transactionsData;
                
                // Update stats
                this.stats.totalPlans = this.plans.length;
                this.stats.activePlans = this.plans.filter(p => p.status === 'active').length;
                this.stats.totalSaved = this.plans.reduce((sum, p) => sum + (p.progress || 0), 0);
                
                this.loadCharts();
            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            }
        },
        
        async refreshData() {
            await this.loadDashboardData();
            this.showToast('Refreshed', 'Data updated successfully', 'success');
        },
        
        // Plans Management
        async createPlan() {
            this.createPlanSubmitting = true;
            try {
                const newPlan = await this.api('/api/plans', {
                    method: 'POST',
                    body: this.createPlanForm
                });
                
                this.plans.unshift(newPlan);
                this.filterPlans();
                
                this.showCreatePlanModal = false;
                this.createPlanForm = {
                    title: '',
                    description: '',
                    planType: 'savings',
                    amount: '',
                    frequency: 'weekly',
                    duration: 12,
                    currency: 'BTC',
                    targetAmount: '',
                    autoContribute: true
                };
                
                this.showToast('Plan Created!', `Your ${newPlan.plan_type} plan has been created.`, 'success');
                
                this.loadCharts();
            } catch (error) {
                // Error handled in api method
            } finally {
                this.createPlanSubmitting = false;
            }
        },
        
        async quickContribute(plan) {
            try {
                await this.api('/api/contribute', {
                    method: 'POST',
                    body: {
                        planId: plan.id,
                        amount: plan.amount,
                        note: 'Quick contribution'
                    }
                });
                
                this.showToast('Contribution Added!', `${this.formatCurrency(plan.amount, plan.currency)} added to ${plan.title}`, 'success');
                
                await this.loadDashboardData();
            } catch (error) {
                // Error handled in api method
            }
        },
        
        async togglePlan(plan) {
            try {
                const action = plan.status === 'active' ? 'pause' : 'resume';
                await this.api(`/api/plans/${plan.id}`, {
                    method: 'PATCH',
                    body: { action }
                });
                
                plan.status = plan.status === 'active' ? 'paused' : 'active';
                
                this.showToast('Plan Updated', `Plan ${action}d successfully`, 'success');
                
                this.filterPlans();
            } catch (error) {
                // Error handled in api method
            }
        },
        
        filterPlans() {
            if (this.planFilter === 'all') {
                this.filteredPlans = this.plans;
            } else {
                this.filteredPlans = this.plans.filter(plan => plan.status === this.planFilter);
            }
        },
        
        // Contact Form
        async submitContact() {
            this.contactSubmitting = true;
            try {
                await this.api('/api/contact', {
                    method: 'POST',
                    body: this.contactForm
                });
                
                this.contactForm = { name: '', email: '', subject: '', message: '' };
                this.showToast('Message Sent!', 'Thank you for your message. We\'ll get back to you soon.', 'success');
            } catch (error) {
                // Error handled in api method
            } finally {
                this.contactSubmitting = false;
            }
        },
        
        // Notifications
        toggleNotifications() {
            this.showNotifications = !this.showNotifications;
            if (this.showNotifications) {
                this.markNotificationsAsRead();
            }
        },
        
        async markNotificationsAsRead() {
            const unreadNotifications = this.notifications.filter(n => !n.read);
            for (const notification of unreadNotifications) {
                try {
                    await this.api(`/api/notifications/${notification.id}/read`, { method: 'POST' });
                    notification.read = true;
                } catch (error) {
                    console.error('Failed to mark notification as read:', error);
                }
            }
            this.unreadCount = 0;
        },
        
        // Admin Functions
        async exportData(type) {
            try {
                const url = `/api/admin/export/${type}`;
                const response = await fetch(url, {
                    headers: { 'Authorization': `Bearer ${this.token}` }
                });
                
                if (!response.ok) throw new Error('Export failed');
                
                const blob = await response.blob();
                const downloadUrl = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = `${type}_export.csv`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(downloadUrl);
                
                this.showToast('Export Complete', `${type} data exported successfully`, 'success');
            } catch (error) {
                this.showToast('Export Failed', error.message, 'error');
            }
        },
        
        async forceSimulation() {
            try {
                await this.api('/api/admin/force-simulate', { method: 'POST' });
                this.showToast('Simulation Complete', 'Automatic contributions processed', 'success');
                await this.loadDashboardData();
            } catch (error) {
                // Error handled in api method
            }
        },
        
        // Charts
        initCharts() {
            // Initialize empty charts
            const heroCtx = document.getElementById('heroChart');
            if (heroCtx) {
                this.heroChart = new Chart(heroCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Savings', 'Emergency', 'Investment'],
                        datasets: [{
                            data: [300, 150, 100],
                            backgroundColor: ['#3B82F6', '#10B981', '#8B5CF6']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
            }
        },
        
        loadCharts() {
            // Portfolio chart
            const portfolioCtx = document.getElementById('portfolioChart');
            if (portfolioCtx && this.plans.length > 0) {
                if (this.portfolioChart) this.portfolioChart.destroy();
                
                this.portfolioChart = new Chart(portfolioCtx, {
                    type: 'line',
                    data: {
                        labels: this.plans.map(p => p.title),
                        datasets: [{
                            label: 'Progress',
                            data: this.plans.map(p => p.progress || 0),
                            borderColor: '#3B82F6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: { display: true, color: 'rgba(0,0,0,0.1)' }
                            },
                            x: {
                                grid: { display: false }
                            }
                        }
                    }
                });
            }
            
            // Update hero chart with real data
            if (this.heroChart && this.plans.length > 0) {
                const planTypes = {};
                this.plans.forEach(plan => {
                    planTypes[plan.plan_type] = (planTypes[plan.plan_type] || 0) + (plan.progress || 0);
                });
                
                this.heroChart.data.labels = Object.keys(planTypes);
                this.heroChart.data.datasets[0].data = Object.values(planTypes);
                this.heroChart.update();
            }
        },
        
        // Utility Functions
        formatCurrency(amount, currency = 'BTC') {
            const decimals = currency === 'BTC' ? 8 : currency === 'ETH' ? 6 : 2;
            return parseFloat(amount || 0).toFixed(decimals) + ' ' + currency;
        },
        
        formatDate(dateString) {
            if (!dateString) return '';
            return new Date(dateString).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },
        
        // Toast Notifications
        showToast(title, message = '', type = 'info') {
            const id = Date.now() + Math.random();
            const toast = { id, title, message, type };
            
            this.toasts.push(toast);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                this.removeToast(id);
            }, 5000);
        },
        
        removeToast(id) {
            this.toasts = this.toasts.filter(toast => toast.id !== id);
        },
        
        // Periodic Refresh
        startPeriodicRefresh() {
            setInterval(() => {
                if (this.isAuthenticated) {
                    this.loadDashboardData();
                }
            }, 30000); // Refresh every 30 seconds
        }
    };
}
</script>

</body>
</html>`);
});

// Additional API Routes for enhanced functionality
app.get('/api/analytics/:planId', (req, res) => {
  try {
    const planId = req.params.planId;
    const { timeframe = '30d' } = req.query;
    
    const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND user_id = ?')
      .get(planId, req.user.userId);
    
    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }
    
    let dateFilter = '';
    switch (timeframe) {
      case '7d':
        dateFilter = "AND contributed_at >= date('now', '-7 days')";
        break;
      case '30d':
        dateFilter = "AND contributed_at >= date('now', '-30 days')";
        break;
      case '90d':
        dateFilter = "AND contributed_at >= date('now', '-90 days')";
        break;
      case '1y':
        dateFilter = "AND contributed_at >= date('now', '-1 year')";
        break;
    }
    
    const contributions = db.prepare(`SELECT 
                                      DATE(contributed_at) as date,
                                      SUM(amount) as daily_amount,
                                      COUNT(*) as count
                                      FROM contributions 
                                      WHERE plan_id = ? ${dateFilter}
                                      GROUP BY DATE(contributed_at)
                                      ORDER BY date ASC`).all(planId);
    
    const analytics = {
      plan,
      contributions,
      summary: {
        totalContributions: contributions.reduce((sum, c) => sum + c.daily_amount, 0),
        averageDaily: contributions.length > 0 ? 
          contributions.reduce((sum, c) => sum + c.daily_amount, 0) / contributions.length : 0,
        contributionCount: contributions.reduce((sum, c) => sum + c.count, 0),
        progressPercentage: plan.target_amount ? 
          (plan.progress / plan.target_amount) * 100 : 
          (plan.progress / plan.total_contributions) * 100
      }
    };
    
    res.json(analytics);
    
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to load analytics' });
  }
});

app.post('/api/plans/:id/withdraw', (req, res) => {
  try {
    const planId = req.params.id;
    const { amount, reason } = req.body || {};
    
    const plan = db.prepare('SELECT * FROM plans WHERE id = ? AND user_id = ?')
      .get(planId, req.user.userId);
    
    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }
    
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Valid withdrawal amount required' });
    }
    
    if (amount > plan.progress) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const withdrawal = db.transaction(() => {
      // Create withdrawal transaction
      const result = db.prepare(`INSERT INTO contributions 
                                (plan_id, user_id, amount, transaction_type, note) 
                                VALUES (?, ?, ?, 'withdrawal', ?)`).run(
        planId, req.user.userId, -Math.abs(amount), reason || 'Withdrawal'
      );
      
      // Update plan progress
      const newProgress = plan.progress - Math.abs(amount);
      db.prepare('UPDATE plans SET progress = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(newProgress, planId);
      
      return db.prepare('SELECT * FROM contributions WHERE id = ?').get(result.lastInsertRowid);
    })();
    
    utils.createNotification(req.user.userId, 'Withdrawal Processed', 
      `${utils.formatCurrency(amount, plan.currency)} withdrawn from "${plan.title}".`);
    
    utils.logAudit(req.user.userId, 'plan.withdraw', 
      { planId, amount, reason }, req);
    
    res.json(withdrawal);
    
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

app.get('/api/goals', (req, res) => {
  try {
    const goals = db.prepare(`SELECT g.*, p.title as plan_title, p.currency 
                              FROM goals g
                              LEFT JOIN plans p ON g.plan_id = p.id
                              WHERE g.user_id = ?
                              ORDER BY g.created_at DESC`).all(req.user.userId);
    
    res.json(goals);
    
  } catch (error) {
    console.error('Goals error:', error);
    res.status(500).json({ error: 'Failed to load goals' });
  }
});

app.post('/api/goals', (req, res) => {
  try {
    const { title, description, targetAmount, targetDate, planId } = req.body || {};
    
    if (!title || !targetAmount) {
      return res.status(400).json({ error: 'Title and target amount are required' });
    }
    
    const result = db.prepare(`INSERT INTO goals 
                              (user_id, plan_id, title, description, target_amount, target_date) 
                              VALUES (?, ?, ?, ?, ?, ?)`).run(
      req.user.userId, planId || null, title, description || null, 
      parseFloat(targetAmount), targetDate || null
    );
    
    const goal = db.prepare('SELECT * FROM goals WHERE id = ?').get(result.lastInsertRowid);
    
    utils.createNotification(req.user.userId, 'Goal Created', 
      `Your goal "${title}" has been created.`, 'success');
    
    utils.logAudit(req.user.userId, 'goal.create', { goalId: goal.id, title }, req);
    
    res.status(201).json(goal);
    
  } catch (error) {
    console.error('Goal creation error:', error);
    res.status(500).json({ error: 'Failed to create goal' });
  }
});

// Enhanced settings management
app.get('/api/settings', adminMiddleware, (req, res) => {
  try {
    const settings = db.prepare('SELECT * FROM settings ORDER BY key ASC').all();
    res.json(settings);
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({ error: 'Failed to load settings' });
  }
});

app.put('/api/settings/:key', adminMiddleware, (req, res) => {
  try {
    const { key } = req.params;
    const { value } = req.body || {};
    
    if (!value) {
      return res.status(400).json({ error: 'Value is required' });
    }
    
    db.prepare('UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?')
      .run(value, key);
    
    utils.logAudit(req.user.userId, 'settings.update', { key, value }, req);
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// Backup and restore endpoints
app.post('/api/admin/backup', adminMiddleware, (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupData = {
      timestamp,
      version: '2.0.0',
      tables: {
        users: db.prepare('SELECT * FROM users').all(),
        plans: db.prepare('SELECT * FROM plans').all(),
        contributions: db.prepare('SELECT * FROM contributions').all(),
        notifications: db.prepare('SELECT * FROM notifications').all(),
        goals: db.prepare('SELECT * FROM goals').all(),
        settings: db.prepare('SELECT * FROM settings').all()
      }
    };
    
    res.setHeader('Content-Disposition', `attachment; filename="archevault_backup_${timestamp}.json"`);
    res.setHeader('Content-Type', 'application/json');
    
    utils.logAudit(req.user.userId, 'admin.backup.create', { timestamp }, req);
    
    res.send(JSON.stringify(backupData, null, 2));
    
  } catch (error) {
    console.error('Backup error:', error);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

// WebSocket-like functionality using Server-Sent Events
app.get('/api/events', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  
  const userId = req.user.userId;
  
  // Send periodic updates
  const intervalId = setInterval(() => {
    try {
      const unreadCount = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND read = 0')
        .get(userId).count;
      
      res.write(`data: ${JSON.stringify({ type: 'notification_count', count: unreadCount })}\n\n`);
    } catch (error) {
      console.error('SSE error:', error);
      clearInterval(intervalId);
      res.end();
    }
  }, 10000); // Every 10 seconds
  
  req.on('close', () => {
    clearInterval(intervalId);
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down Arche Vault...');
  
  try {
    db.close();
    console.log('✅ Database connection closed');
  } catch (error) {
    console.error('❌ Error closing database:', error);
  }
  
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start the server
const server = app.listen(config.port, () => {
  console.log('🚀 Arche Vault Enhanced Server Started');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🌐 Server: http://localhost:${config.port}`);
  console.log(`💾 Database: ${config.dbPath}`);
  console.log(⏱️  Simulation: Every ${config.simulationInterval / 1000}s`);
  console.log(`🔐 Admin User: ${config.adminUsername}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ Ready to accept connections');
  
  // Initial simulation run
  setTimeout(() => {
    console.log('🔄 Running initial simulation...');
    simulationEngine();
  }, 3000);
});

// Export for testing
module.exports = { app, db, utils, config };

// -------- Start Server ----------
app.listen(config.port, () => {
  console.log(🚀 Arche Vault running at http://localhost:${config.port});
});


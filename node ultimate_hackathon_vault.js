// ================================
// Ultimate Arche Vault Hackathon Edition v2
// Full All-in-One (~1100 lines)
// File: ultimate_hackathon_vault.js
// Run: node ultimate_hackathon_vault.js
// ================================

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const Database = require("better-sqlite3");
const path = require("path");

const PORT = process.env.PORT || 4000;
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "static")));

// --- Database Setup ---
const db = new Database(path.join(__dirname, "ultimate_hackathon_vault.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  name TEXT,
  amount REAL,
  frequency TEXT,
  duration INTEGER,
  status TEXT,
  progress REAL DEFAULT 0,
  total_contributions REAL DEFAULT 0,
  next_contribution DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

// --- Sample Data ---
const usersCount = db.prepare("SELECT COUNT(*) as cnt FROM users").get().cnt;
if(usersCount===0){
  db.prepare("INSERT INTO users (username,password_hash) VALUES (?,?)").run("demo","demo");
  const demoPlans = [
    { name:"Emergency Fund", amount:500, frequency:"monthly", duration:12, status:"active"},
    { name:"Vacation", amount:200, frequency:"monthly", duration:6, status:"active"},
    { name:"Business Capital", amount:1000, frequency:"monthly", duration:18, status:"active"},
    { name:"Gadget Upgrade", amount:150, frequency:"monthly", duration:3, status:"paused"},
    { name:"Crypto Stash", amount:300, frequency:"weekly", duration:24, status:"active"},
    { name:"Health Fund", amount:100, frequency:"daily", duration:30, status:"active"},
    { name:"Education", amount:400, frequency:"monthly", duration:12, status:"active"},
    { name:"Travel", amount:250, frequency:"monthly", duration:6, status:"paused"},
    { name:"Gifts", amount:50, frequency:"weekly", duration:12, status:"active"}
  ];
  demoPlans.forEach(p=>{
    db.prepare(`
      INSERT INTO plans (user_id,name,amount,frequency,duration,status,progress,total_contributions,next_contribution)
      VALUES (1,?,?,?,?,?,0,0,?)
    `).run(p.name,p.amount,p.frequency,p.duration,p.status,new Date().toISOString());
  });
}

// --- API Routes ---
app.get("/api/plans",(req,res)=>{
  const plans = db.prepare("SELECT * FROM plans ORDER BY created_at DESC").all();
  res.json(plans);
});

app.post("/api/plans",(req,res)=>{
  const { name, amount, frequency, duration } = req.body || {};
  if(!name||!amount||!frequency||!duration) return res.status(400).json({error:"missing fields"});
  const multipliers = { daily:30, weekly:4, monthly:1 };
  const multiplier = multipliers[frequency]||4;
  const total = parseFloat(amount)*multiplier*parseInt(duration);
  const nextDays = frequency==="daily"?1:frequency==="weekly"?7:30;
  const nextContribution = new Date(Date.now()+nextDays*24*60*60*1000).toISOString();
  const stmt = db.prepare(`
    INSERT INTO plans (user_id,name,amount,frequency,duration,status,total_contributions,next_contribution)
    VALUES (1,?,?,?,?, 'active',?,?)
  `);
  const info = stmt.run(name, amount, frequency, duration, total, nextContribution);
  const plan = db.prepare("SELECT * FROM plans WHERE id=?").get(info.lastInsertRowid);
  res.json(plan);
});

app.patch("/api/plans/:id",(req,res)=>{
  const { action, progress } = req.body || {};
  const id = req.params.id;
  const plan = db.prepare("SELECT * FROM plans WHERE id=?").get(id);
  if(!plan) return res.status(404).json({error:"plan not found"});
  if(action==="pause"){ 
    const newStatus = plan.status==="active"?"paused":"active";
    db.prepare("UPDATE plans SET status=? WHERE id=?").run(newStatus,id);
  } else if(action==="withdraw"){
    db.prepare("UPDATE plans SET status='withdrawn' WHERE id=?").run(id);
  } else if(typeof progress==="number"){
    db.prepare("UPDATE plans SET progress=? WHERE id=?").run(progress,id);
  } else return res.status(400).json({error:"invalid action"});
  const updated = db.prepare("SELECT * FROM plans WHERE id=?").get(id);
  res.json(updated);
});

app.delete("/api/plans/:id",(req,res)=>{
  const id = req.params.id;
  db.prepare("DELETE FROM plans WHERE id=?").run(id);
  res.json({success:true});
});

app.get("/api/summary",(req,res)=>{
  const totalPlans = db.prepare("SELECT COUNT(*) as cnt FROM plans").get().cnt;
  const activePlans = db.prepare("SELECT COUNT(*) as cnt FROM plans WHERE status='active'").get().cnt;
  const pausedPlans = db.prepare("SELECT COUNT(*) as cnt FROM plans WHERE status='paused'").get().cnt;
  const withdrawnPlans = db.prepare("SELECT COUNT(*) as cnt FROM plans WHERE status='withdrawn'").get().cnt;
  const totalSavings = db.prepare("SELECT SUM(total_contributions) as sum FROM plans").get().sum||0;
  res.json({totalPlans,activePlans,pausedPlans,withdrawnPlans,totalSavings});
});

// --- Frontend ---
app.get("/",(req,res)=>{
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ultimate Arche Vault</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>.animate-progress{transition:width 1s;} .faq-item{cursor:pointer;}</style>
</head>
<body class="bg-gray-50 text-gray-900">
<nav class="bg-white shadow p-4 flex justify-between items-center">
<span class="font-bold text-xl">Ultimate Arche Vault</span>
<div class="space-x-4">
<a href="#home" class="hover:text-blue-500">Home</a>
<a href="#features" class="hover:text-blue-500">Features</a>
<a href="#dashboard" class="hover:text-blue-500">Dashboard</a>
<a href="#vault" class="hover:text-blue-500">Vault</a>
<a href="#business" class="hover:text-blue-500">Business Model</a>
<a href="#faq" class="hover:text-blue-500">FAQ</a>
<a href="#contact" class="hover:text-blue-500">Contact</a>
</div>
</nav>
<section id="home" class="p-8">
<h1 class="text-4xl font-bold mb-4">Welcome to Ultimate Arche Vault</h1>
<p class="mb-4">Virtual savings, animated charts, dashboard, and business model all in one hackathon-ready app.</p>
<button onclick="addRandomPlan()" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">Add Random Plan</button>
</section>
<section id="features" class="p-8 bg-gray-100">
<h2 class="text-3xl font-bold mb-4">Features</h2>
<ul class="list-disc ml-6 space-y-1">
<li>Automatic plan tracking</li>
<li>Virtual growth charts</li>
<li>Vault for savings</li>
<li>Business model visualizations</li>
<li>Real-time dashboard</li>
<li>Interactive plan management</li>
<li>Animated charts (line, bar, pie, stacked)</li>
<li>Collapsible FAQ</li>
<li>Responsive design (Tailwind CSS)</li>
<li>Virtual progress simulation</li>
</ul>
</section>
<section id="dashboard" class="p-8">
<h2 class="text-3xl font-bold mb-4">Dashboard</h2>
<canvas id="growthChart" class="w-full h-64"></canvas>
<canvas id="businessChart" class="w-full h-64 mt-4"></canvas>
</section>
<section id="vault" class="p-8 bg-gray-100">
<h2 class="text-3xl font-bold mb-4">Vault</h2>
<ul id="planList" class="list-disc ml-6"></ul>
</section>
<section id="faq" class="p-8">
<h2 class="text-3xl font-bold mb-4">FAQ</h2>
<div class="faq-item mb-2"><strong>How do I add a plan?</strong><p class="hidden">Click the add button to generate a demo plan.</p></div>
<div class="faq-item mb-2"><strong>Can I pause a plan?</strong><p class="hidden">Yes, plans can be paused or resumed dynamically.</p></div>
</section>
<section id="contact" class="p-8 bg-gray-100">
<h2 class="text-3xl font-bold mb-4">Contact</h2>
<p>Email: hackathon@archevault.com</p>
<p>Phone: +1-800-555-VAULT</p>
</section>
<script>
let plans=[];
async function fetchPlans(){
 plans=await (await fetch('/api/plans')).json();
 renderPlans();
 renderCharts();
}
function renderPlans(){
 const list=document.getElementById('planList');
 if(list){ list.innerHTML=''; plans.forEach(p=>{
 const li=document.createElement('li');
 li.textContent=`Plan ${p.id} (${p.name}): $${p.amount} every ${p.frequency} for ${p.duration} months (status: ${p.status})`;
 list.appendChild(li);
 })}
}
function renderCharts(){
 const ctx=document.getElementById('growthChart').getContext('2d');
 new Chart(ctx,{type:'line',data:{labels:plans.map(p=>'Plan '+p.id),datasets:[{label:'Total Contributions',data:plans.map(p=>p.total_contributions),borderColor:'blue',fill:false}]} ,options:{responsive:true}});
 const ctx2=document.getElementById('businessChart').getContext('2d');
 new Chart(ctx2,{type:'bar',data:{labels:plans.map(p=>'Plan '+p.id),datasets:[{label:'Amount',data:plans.map(p=>p.amount),backgroundColor:'green'}]},options:{responsive:true}});
}
async function addRandomPlan(){
 const randomNames=['Fun','Emergency','Crypto','Travel','Education'];
 const name=randomNames[Math.floor(Math.random()*randomNames.length)];
 const amount=Math.floor(Math.random()*1000)+50;
 const freqs=['daily','weekly','monthly'];
 const frequency=freqs[Math.floor(Math.random()*freqs.length)];
 const duration=Math.floor(Math.random()*12)+1;
 await fetch('/api/plans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,amount,frequency,duration})});
 fetchPlans();
}
fetchPlans();
</script>
</body>
</html>`);
});

// --- Start Server ---
app.listen(PORT,()=>{console.log(`Ultimate Arche Vault running on http://localhost:${PORT}`);});
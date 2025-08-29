// arche-vault-server.js

// -------------------- Imports --------------------
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const WebSocket = require("ws");
const cron = require("node-cron");
const { body, validationResult } = require("express-validator");

// Stacks SDK (modern packages)
const { StacksTestnet } = require("@stacks/network");
const {
  makeContractCall,
  standardPrincipalCV,
  uintCV,
  broadcastTransaction,
} = require("@stacks/transactions");
const {
  AccountsApi,
  SmartContractsApi,
  TransactionsApi,
  Configuration,
} = require("@stacks/blockchain-api-client");

// -------------------- Config --------------------
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/archevault";

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(helmet());
app.use(morgan("dev"));

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
});
app.use(limiter);

// -------------------- MongoDB Models --------------------
const VaultSchema = new mongoose.Schema({
  userId: String,
  amount: Number,
  frequency: String,
  duration: Number,
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
});
const Vault = mongoose.model("Vault", VaultSchema);

// -------------------- WebSocket --------------------
const wss = new WebSocket.Server({ noServer: true });
wss.on("connection", (ws) => {
  console.log("Client connected via WebSocket");
  ws.on("close", () => console.log("Client disconnected"));
});

// -------------------- Stacks API --------------------
const stacksConfig = new Configuration({
  basePath: "https://api.testnet.hiro.so",
});
const accountsApi = new AccountsApi(stacksConfig);
const contractsApi = new SmartContractsApi(stacksConfig);
const txApi = new TransactionsApi(stacksConfig);

// -------------------- Routes --------------------
app.get("/", (req, res) => {
  res.send("Arche Vault backend running 🚀");
});

// Create a savings vault
app.post(
  "/api/vaults",
  [
    body("userId").notEmpty(),
    body("amount").isNumeric(),
    body("frequency").isString(),
    body("duration").isNumeric(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const vault = new Vault(req.body);
      await vault.save();
      res.json({ success: true, plan: vault });
    } catch (err) {
      res.status(500).json({ error: "Failed to create vault" });
    }
  }
);

// Get all vaults for a user
app.get("/api/vaults/:userId", async (req, res) => {
  try {
    const vaults = await Vault.find({ userId: req.params.userId });
    res.json(vaults);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch vaults" });
  }
});

// Pause/resume a vault
app.put("/api/vaults/:id/toggle", async (req, res) => {
  try {
    const vault = await Vault.findById(req.params.id);
    if (!vault) return res.status(404).json({ error: "Vault not found" });
    vault.isActive = !vault.isActive;
    await vault.save();
    res.json({ success: true, message: `Vault ${vault.isActive ? "resumed" : "paused"}` });
  } catch (err) {
    res.status(500).json({ error: "Failed to update vault" });
  }
});

// Withdraw funds (simulated)
app.post("/api/vaults/:id/withdraw", async (req, res) => {
  try {
    const vault = await Vault.findById(req.params.id);
    if (!vault) return res.status(404).json({ error: "Vault not found" });
    const netAmount = vault.amount * vault.duration; // very naive
    await Vault.findByIdAndDelete(req.params.id);
    res.json({ success: true, netAmount });
  } catch (err) {
    res.status(500).json({ error: "Failed to withdraw" });
  }
});

// Stats
app.get("/api/stats", async (req, res) => {
  try {
    const totalUsers = await Vault.distinct("userId").countDocuments();
    const activeVaults = await Vault.countDocuments({ isActive: true });
    const totalSavedAgg = await Vault.aggregate([
      { $group: { _id: null, total: { $sum: "$amount" } } },
    ]);
    const totalSaved = totalSavedAgg[0] ? totalSavedAgg[0].total : 0;
    res.json({ totalUsers, activeVaults, totalSaved });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

// -------------------- Background Jobs --------------------
// Example: check vaults every day
cron.schedule("0 0 * * *", async () => {
  console.log("Daily cron running...");
  const activeVaults = await Vault.find({ isActive: true });
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: "cron", activeVaults }));
    }
  });
});

// -------------------- Server Startup --------------------
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB");
    const server = app.listen(PORT, () =>
      console.log(`Server running on http://localhost:${PORT}`)
    );

    // Upgrade HTTP to WebSocket
    server.on("upgrade", (req, socket, head) => {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit("connection", ws, req);
      });
    });
  })
  .catch((err) => console.error("MongoDB connection error:", err));

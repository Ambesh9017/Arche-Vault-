// =====================================================
// ARCHE VAULT BACKEND - COMPLETE SYSTEM
// =====================================================

// =====================================================
// 1. CLARITY SMART CONTRACT (main-contract.clar)
// =====================================================

/*
;; Arche Vault Smart Contract
;; Automated Bitcoin Savings with Stacks

(define-constant contract-owner tx-sender)
(define-constant err-not-owner (err u100))
(define-constant err-invalid-plan (err u101))
(define-constant err-insufficient-funds (err u102))
(define-constant err-plan-not-found (err u103))
(define-constant err-unauthorized (err u104))
(define-constant err-plan-not-mature (err u105))

;; Data Variables
(define-data-var next-plan-id uint u1)
(define-data-var platform-fee-rate uint u50) ;; 0.5% = 50 basis points

;; Maps
(define-map savings-plans 
  { plan-id: uint }
  {
    owner: principal,
    amount-per-deposit: uint,
    frequency: (string-ascii 10),
    total-deposits: uint,
    current-balance: uint,
    start-block: uint,
    maturity-block: uint,
    is-active: bool,
    created-at: uint
  }
)

(define-map user-plans
  { user: principal, plan-id: uint }
  { exists: bool }
)

(define-map plan-deposits
  { plan-id: uint, deposit-number: uint }
  {
    amount: uint,
    block-height: uint,
    timestamp: uint
  }
)

;; Public Functions

;; Create a new savings plan
(define-public (create-savings-plan 
  (amount-per-deposit uint)
  (frequency (string-ascii 10))
  (duration-months uint))
  (let (
    (plan-id (var-get next-plan-id))
    (blocks-per-month u4320) ;; ~30 days * 144 blocks/day
    (maturity-block (+ block-height (* duration-months blocks-per-month)))
  )
    (try! (stx-transfer? amount-per-deposit tx-sender (as-contract tx-sender)))
    
    (map-set savings-plans
      { plan-id: plan-id }
      {
        owner: tx-sender,
        amount-per-deposit: amount-per-deposit,
        frequency: frequency,
        total-deposits: u1,
        current-balance: amount-per-deposit,
        start-block: block-height,
        maturity-block: maturity-block,
        is-active: true,
        created-at: (unwrap-panic (get-block-info? time block-height))
      }
    )
    
    (map-set user-plans
      { user: tx-sender, plan-id: plan-id }
      { exists: true }
    )
    
    (map-set plan-deposits
      { plan-id: plan-id, deposit-number: u1 }
      {
        amount: amount-per-deposit,
        block-height: block-height,
        timestamp: (unwrap-panic (get-block-info? time block-height))
      }
    )
    
    (var-set next-plan-id (+ plan-id u1))
    (ok plan-id)
  )
)

;; Make a recurring deposit
(define-public (make-deposit (plan-id uint))
  (let (
    (plan (unwrap! (map-get? savings-plans { plan-id: plan-id }) err-plan-not-found))
    (new-total-deposits (+ (get total-deposits plan) u1))
    (deposit-amount (get amount-per-deposit plan))
  )
    (asserts! (get is-active plan) err-invalid-plan)
    (asserts! (is-eq (get owner plan) tx-sender) err-unauthorized)
    
    (try! (stx-transfer? deposit-amount tx-sender (as-contract tx-sender)))
    
    (map-set savings-plans
      { plan-id: plan-id }
      (merge plan {
        total-deposits: new-total-deposits,
        current-balance: (+ (get current-balance plan) deposit-amount)
      })
    )
    
    (map-set plan-deposits
      { plan-id: plan-id, deposit-number: new-total-deposits }
      {
        amount: deposit-amount,
        block-height: block-height,
        timestamp: (unwrap-panic (get-block-info? time block-height))
      }
    )
    
    (ok new-total-deposits)
  )
)

;; Withdraw from a mature plan
(define-public (withdraw-plan (plan-id uint))
  (let (
    (plan (unwrap! (map-get? savings-plans { plan-id: plan-id }) err-plan-not-found))
    (withdrawal-amount (get current-balance plan))
    (platform-fee (/ (* withdrawal-amount (var-get platform-fee-rate)) u10000))
    (user-amount (- withdrawal-amount platform-fee))
  )
    (asserts! (is-eq (get owner plan) tx-sender) err-unauthorized)
    (asserts! (>= block-height (get maturity-block plan)) err-plan-not-mature)
    (asserts! (get is-active plan) err-invalid-plan)
    
    (try! (as-contract (stx-transfer? user-amount tx-sender tx-sender)))
    (try! (as-contract (stx-transfer? platform-fee tx-sender contract-owner)))
    
    (map-set savings-plans
      { plan-id: plan-id }
      (merge plan {
        current-balance: u0,
        is-active: false
      })
    )
    
    (ok user-amount)
  )
)

;; Emergency withdrawal (with penalty)
(define-public (emergency-withdraw (plan-id uint))
  (let (
    (plan (unwrap! (map-get? savings-plans { plan-id: plan-id }) err-plan-not-found))
    (current-balance (get current-balance plan))
    (penalty-rate u1000) ;; 10% penalty
    (penalty (/ (* current-balance penalty-rate) u10000))
    (platform-fee (/ (* current-balance (var-get platform-fee-rate)) u10000))
    (total-fees (+ penalty platform-fee))
    (user-amount (- current-balance total-fees))
  )
    (asserts! (is-eq (get owner plan) tx-sender) err-unauthorized)
    (asserts! (get is-active plan) err-invalid-plan)
    
    (try! (as-contract (stx-transfer? user-amount tx-sender tx-sender)))
    (try! (as-contract (stx-transfer? total-fees tx-sender contract-owner)))
    
    (map-set savings-plans
      { plan-id: plan-id }
      (merge plan {
        current-balance: u0,
        is-active: false
      })
    )
    
    (ok user-amount)
  )
)

;; Read-only functions
(define-read-only (get-plan (plan-id uint))
  (map-get? savings-plans { plan-id: plan-id })
)

(define-read-only (get-user-plans (user principal))
  (let (
    (plan-ids (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10)) ;; Limited for demo
  )
    (filter is-user-plan 
      (map get-plan-if-user-owns 
        (map (lambda (id) { user: user, plan-id: id }) plan-ids)))))

(define-read-only (is-user-plan (plan-data (optional {owner: principal, amount-per-deposit: uint, frequency: (string-ascii 10), total-deposits: uint, current-balance: uint, start-block: uint, maturity-block: uint, is-active: bool, created-at: uint})))
  (is-some plan-data))

(define-read-only (get-plan-if-user-owns (user-plan-id {user: principal, plan-id: uint}))
  (let (
    (user (get user user-plan-id))
    (plan-id (get plan-id user-plan-id))
    (plan (map-get? savings-plans { plan-id: plan-id }))
  )
    (if (and (is-some plan) 
             (is-eq user (get owner (unwrap-panic plan))))
        plan
        none)))

(define-read-only (get-deposit (plan-id uint) (deposit-number uint))
  (map-get? plan-deposits { plan-id: plan-id, deposit-number: deposit-number })
)
*/

// =====================================================
// 2. NODE.JS EXPRESS SERVER
// =====================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const { StacksMainnet, StacksTestnet } = require('@stacks/network');
const { 
  makeContractCall,
  broadcastTransaction,
  AnchorMode,
  PostConditionMode,
  createSTXPostCondition,
  FungibleConditionCode,
  standardPrincipalCV,
  uintCV,
  stringAsciiCV
} = require('@stacks/transactions');
const { StacksApiClient } = require('@stacks/api');

const app = express();
const PORT = process.env.PORT || 3001;

// =====================================================
// 3. DATABASE MODELS (MongoDB/Mongoose)
// =====================================================

// User Model
const userSchema = new mongoose.Schema({
  walletAddress: { type: String, required: true, unique: true },
  email: { type: String, sparse: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now },
  totalSaved: { type: Number, default: 0 },
  activePlans: { type: Number, default: 0 },
  preferences: {
    notifications: { type: Boolean, default: true },
    currency: { type: String, default: 'USD' }
  }
});

const User = mongoose.model('User', userSchema);

// Savings Plan Model
const savingsPlanSchema = new mongoose.Schema({
  planId: { type: Number, required: true },
  userAddress: { type: String, required: true },
  amountPerDeposit: { type: Number, required: true },
  frequency: { 
    type: String, 
    enum: ['daily', 'weekly', 'monthly'],
    required: true 
  },
  durationMonths: { type: Number, required: true },
  totalDeposits: { type: Number, default: 1 },
  currentBalance: { type: Number, default: 0 },
  startBlock: { type: Number, required: true },
  maturityBlock: { type: Number, required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  nextDepositDate: { type: Date, required: true },
  contractTxId: { type: String, required: true },
  status: {
    type: String,
    enum: ['active', 'paused', 'completed', 'withdrawn'],
    default: 'active'
  }
});

const SavingsPlan = mongoose.model('SavingsPlan', savingsPlanSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
  txId: { type: String, required: true, unique: true },
  planId: { type: Number, required: true },
  userAddress: { type: String, required: true },
  type: {
    type: String,
    enum: ['deposit', 'withdrawal', 'emergency_withdrawal', 'plan_creation'],
    required: true
  },
  amount: { type: Number, required: true },
  blockHeight: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'failed'],
    default: 'pending'
  },
  gasUsed: { type: Number },
  fees: { type: Number, default: 0 }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// =====================================================
// 4. MIDDLEWARE CONFIGURATION
// =====================================================

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// =====================================================
// 5. STACKS NETWORK CONFIGURATION
// =====================================================

const network = process.env.NODE_ENV === 'production' 
  ? new StacksMainnet() 
  : new StacksTestnet();

const stacksApi = new StacksApiClient({ network });

const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS || 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM';
const CONTRACT_NAME = 'arche-vault';

// =====================================================
// 6. UTILITY FUNCTIONS
// =====================================================

// Convert frequency to next deposit date
function getNextDepositDate(frequency) {
  const now = new Date();
  switch (frequency) {
    case 'daily':
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case 'weekly':
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case 'monthly':
      const nextMonth = new Date(now);
      nextMonth.setMonth(nextMonth.getMonth() + 1);
      return nextMonth;
    default:
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
}

// Calculate maturity block (approximately)
function calculateMaturityBlock(currentBlock, durationMonths) {
  const blocksPerMonth = 4320; // ~30 days * 144 blocks/day
  return currentBlock + (durationMonths * blocksPerMonth);
}

// STX to USD conversion (mock - in production, use real price API)
function stxToUsd(stxAmount) {
  const STX_USD_RATE = 2.5; // Mock rate
  return stxAmount * STX_USD_RATE;
}

// =====================================================
// 7. API ROUTES
// =====================================================

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Get user profile
app.get('/api/users/:address', async (req, res) => {
  try {
    const { address } = req.params;
    
    let user = await User.findOne({ walletAddress: address });
    if (!user) {
      user = new User({ 
        walletAddress: address,
        lastLogin: new Date()
      });
      await user.save();
    } else {
      user.lastLogin = new Date();
      await user.save();
    }

    // Get user's active plans
    const plans = await SavingsPlan.find({ 
      userAddress: address, 
      isActive: true 
    });

    const totalSaved = plans.reduce((sum, plan) => sum + plan.currentBalance, 0);
    
    user.totalSaved = totalSaved;
    user.activePlans = plans.length;
    await user.save();

    res.json({
      user,
      stats: {
        totalSavedUSD: stxToUsd(totalSaved),
        activePlans: plans.length,
        totalPlans: await SavingsPlan.countDocuments({ userAddress: address })
      }
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's savings plans
app.get('/api/users/:address/plans', async (req, res) => {
  try {
    const { address } = req.params;
    const { status = 'active' } = req.query;

    const filter = { userAddress: address };
    if (status !== 'all') {
      filter.status = status;
    }

    const plans = await SavingsPlan.find(filter).sort({ createdAt: -1 });

    const enhancedPlans = plans.map(plan => ({
      ...plan.toObject(),
      totalTargetUSD: stxToUsd(plan.amountPerDeposit * plan.durationMonths * (plan.frequency === 'daily' ? 30 : plan.frequency === 'weekly' ? 4 : 1)),
      currentBalanceUSD: stxToUsd(plan.currentBalance),
      progress: Math.min(100, (plan.totalDeposits / (plan.durationMonths * (plan.frequency === 'daily' ? 30 : plan.frequency === 'weekly' ? 4 : 1))) * 100),
      daysUntilMaturity: Math.max(0, Math.ceil((plan.nextDepositDate - new Date()) / (1000 * 60 * 60 * 24)))
    }));

    res.json({ plans: enhancedPlans });
  } catch (error) {
    console.error('Error fetching plans:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new savings plan
app.post('/api/plans', async (req, res) => {
  try {
    const {
      userAddress,
      amountPerDeposit,
      frequency,
      durationMonths,
      privateKey // In production, use proper wallet integration
    } = req.body;

    // Validation
    if (!userAddress || !amountPerDeposit || !frequency || !durationMonths) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!['daily', 'weekly', 'monthly'].includes(frequency)) {
      return res.status(400).json({ error: 'Invalid frequency' });
    }

    if (amountPerDeposit <= 0 || durationMonths <= 0) {
      return res.status(400).json({ error: 'Invalid amounts' });
    }

    // Get current block height
    const info = await stacksApi.getBlockchainInfo();
    const currentBlock = info.burn_block_height;

    // Generate plan ID
    const planId = Date.now();

    // Create contract call transaction
    const txOptions = {
      contractAddress: CONTRACT_ADDRESS,
      contractName: CONTRACT_NAME,
      functionName: 'create-savings-plan',
      functionArgs: [
        uintCV(amountPerDeposit * 1000000), // Convert to microSTX
        stringAsciiCV(frequency),
        uintCV(durationMonths)
      ],
      senderKey: privateKey,
      network,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
    };

    const transaction = await makeContractCall(txOptions);
    const broadcastResponse = await broadcastTransaction(transaction, network);

    if (broadcastResponse.error) {
      throw new Error(broadcastResponse.reason || 'Transaction failed');
    }

    // Save to database
    const newPlan = new SavingsPlan({
      planId,
      userAddress,
      amountPerDeposit,
      frequency,
      durationMonths,
      currentBalance: amountPerDeposit,
      startBlock: currentBlock,
      maturityBlock: calculateMaturityBlock(currentBlock, durationMonths),
      nextDepositDate: getNextDepositDate(frequency),
      contractTxId: broadcastResponse.txid,
      status: 'active'
    });

    await newPlan.save();

    // Record transaction
    const txRecord = new Transaction({
      txId: broadcastResponse.txid,
      planId,
      userAddress,
      type: 'plan_creation',
      amount: amountPerDeposit,
      blockHeight: currentBlock,
      status: 'pending'
    });

    await txRecord.save();

    res.json({
      success: true,
      planId,
      txId: broadcastResponse.txid,
      plan: newPlan
    });
  } catch (error) {
    console.error('Error creating plan:', error);
    res.status(500).json({ error: error.message || 'Failed to create savings plan' });
  }
});

// Make deposit to existing plan
app.post('/api/plans/:planId/deposit', async (req, res) => {
  try {
    const { planId } = req.params;
    const { userAddress, privateKey } = req.body;

    const plan = await SavingsPlan.findOne({ 
      planId: parseInt(planId),
      userAddress,
      isActive: true 
    });

    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    // Create deposit transaction
    const txOptions = {
      contractAddress: CONTRACT_ADDRESS,
      contractName: CONTRACT_NAME,
      functionName: 'make-deposit',
      functionArgs: [uintCV(plan.planId)],
      senderKey: privateKey,
      network,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
    };

    const transaction = await makeContractCall(txOptions);
    const broadcastResponse = await broadcastTransaction(transaction, network);

    if (broadcastResponse.error) {
      throw new Error(broadcastResponse.reason || 'Deposit failed');
    }

    // Update plan
    plan.totalDeposits += 1;
    plan.currentBalance += plan.amountPerDeposit;
    plan.nextDepositDate = getNextDepositDate(plan.frequency);
    await plan.save();

    // Record transaction
    const txRecord = new Transaction({
      txId: broadcastResponse.txid,
      planId: plan.planId,
      userAddress,
      type: 'deposit',
      amount: plan.amountPerDeposit,
      blockHeight: await getCurrentBlockHeight(),
      status: 'pending'
    });

    await txRecord.save();

    res.json({
      success: true,
      txId: broadcastResponse.txid,
      newBalance: plan.currentBalance,
      totalDeposits: plan.totalDeposits
    });
  } catch (error) {
    console.error('Error making deposit:', error);
    res.status(500).json({ error: error.message || 'Failed to make deposit' });
  }
});

// Withdraw from plan
app.post('/api/plans/:planId/withdraw', async (req, res) => {
  try {
    const { planId } = req.params;
    const { userAddress, privateKey, emergency = false } = req.body;

    const plan = await SavingsPlan.findOne({ 
      planId: parseInt(planId),
      userAddress,
      isActive: true 
    });

    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    const functionName = emergency ? 'emergency-withdraw' : 'withdraw-plan';

    // Create withdrawal transaction
    const txOptions = {
      contractAddress: CONTRACT_ADDRESS,
      contractName: CONTRACT_NAME,
      functionName,
      functionArgs: [uintCV(plan.planId)],
      senderKey: privateKey,
      network,
      anchorMode: AnchorMode.Any,
      postConditionMode: PostConditionMode.Allow,
    };

    const transaction = await makeContractCall(txOptions);
    const broadcastResponse = await broadcastTransaction(transaction, network);

    if (broadcastResponse.error) {
      throw new Error(broadcastResponse.reason || 'Withdrawal failed');
    }

    // Update plan status
    plan.isActive = false;
    plan.status = 'withdrawn';
    await plan.save();

    // Record transaction
    const txRecord = new Transaction({
      txId: broadcastResponse.txid,
      planId: plan.planId,
      userAddress,
      type: emergency ? 'emergency_withdrawal' : 'withdrawal',
      amount: plan.currentBalance,
      blockHeight: await getCurrentBlockHeight(),
      status: 'pending'
    });

    await txRecord.save();

    res.json({
      success: true,
      txId: broadcastResponse.txid,
      withdrawnAmount: plan.currentBalance,
      emergency
    });
  } catch (error) {
    console.error('Error withdrawing:', error);
    res.status(500).json({ error: error.message || 'Failed to withdraw' });
  }
});

// Get transaction history
app.get('/api/users/:address/transactions', async (req, res) => {
  try {
    const { address } = req.params;
    const { page = 1, limit = 20, type = 'all' } = req.query;

    const filter = { userAddress: address };
    if (type !== 'all') {
      filter.type = type;
    }

    const transactions = await Transaction.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Transaction.countDocuments(filter);

    const enhancedTransactions = transactions.map(tx => ({
      ...tx.toObject(),
      amountUSD: stxToUsd(tx.amount),
      explorerUrl: `https://explorer.stacks.co/txid/${tx.txId}?chain=${network.isMainnet() ? 'mainnet' : 'testnet'}`
    }));

    res.json({
      transactions: enhancedTransactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get platform statistics
app.get('/api/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalPlans = await SavingsPlan.countDocuments();
    const activePlans = await SavingsPlan.countDocuments({ isActive: true });
    
    const totalSavedResult = await SavingsPlan.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: null, total: { $sum: '$currentBalance' } } }
    ]);
    
    const totalSaved = totalSavedResult[0]?.total || 0;

    res.json({
      totalUsers,
      totalPlans,
      activePlans,
      totalSaved,
      totalSavedUSD: stxToUsd(totalSaved),
      averagePerPlan: totalPlans > 0 ? totalSaved / totalPlans : 0
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =====================================================
// 8. AUTOMATED DEPOSIT SCHEDULER
// =====================================================

async function getCurrentBlockHeight() {
  try {
    const info = await stacksApi.getBlockchainInfo();
    return info.burn_block_height;
  } catch (error) {
    console.error('Error getting block height:', error);
    return 0;
  }
}

// Check and process due deposits
async function processDueDeposits() {
  try {
    const now = new Date();
    const duePlans = await SavingsPlan.find({
      isActive: true,
      nextDepositDate: { $lte: now }
    });

    console.log(`Processing ${duePlans.length} due deposits...`);

    for (const plan of duePlans) {
      try {
        // In a real implementation, you'd need stored private keys or
        // integration with wallet services for automated deposits
        console.log(`Plan ${plan.planId} is due for deposit`);
        
        // Update next deposit date
        plan.nextDepositDate = getNextDepositDate(plan.frequency);
        await plan.save();
        
      } catch (error) {
        console.error(`Error processing deposit for plan ${plan.planId}:`, error);
      }
    }
  } catch (error) {
    console.error('Error in processDueDeposits:', error);
  }
}

// Run deposit processor every hour
setInterval(processDueDeposits, 60 * 60 * 1000);

// =====================================================
// 9. TRANSACTION STATUS UPDATER
// =====================================================

async function updateTransactionStatuses() {
  try {
    const pendingTxs = await Transaction.find({ status: 'pending' });
    
    for (const tx of pendingTxs) {
      try {
        const txInfo = await stacksApi.getTransaction(tx.txId);
        
        if (txInfo.tx_status === 'success') {
          tx.status = 'confirmed';
          tx.blockHeight = txInfo.block_height;
          tx.gasUsed = txInfo.fee_rate;
          await tx.save();
        } else if (txInfo.tx_status === 'abort_by_response' || txInfo.tx_status === 'abort_by_post_condition') {
          tx.status = 'failed';
          await tx.save();
        }
      } catch (error) {
        console.error(`Error updating tx ${tx.txId}:`, error);
      }
    }
  } catch (error) {
    console.error('Error updating transaction statuses:', error);
  }
}

// Update transaction statuses every 5 minutes
setInterval(updateTransactionStatuses, 5 * 60 * 1000);

// =====================================================
// 10. ERROR HANDLING & DATABASE CONNECTION
// =====================================================

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/arche-vault', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
  
  // Start server
  app.listen(PORT, () => {
    console.log(`Arche Vault Backend running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Network: ${network.isMainnet() ? 'mainnet' : 'testnet'}`);
  });
})
.catch((error) => {
  console.error('MongoDB connection error:', error);
  process.exit(1);
});

// =====================================================
// 11. WEBHOOK HANDLERS FOR REAL-TIME UPDATES
// =====================================================

// Webhook endpoint for Stacks events
app.post('/api/webhooks/stacks', async (req, res) => {
  try {
    const { event_type, transaction } = req.body;
    
    if (event_type === 'transaction_confirmed') {
      // Update transaction status in database
      await Transaction.findOneAndUpdate(
        { txId: transaction.tx_id },
        { 
          status: 'confirmed',
          blockHeight: transaction.block_height,
          gasUsed: transaction.fee_rate
        }
      );
      
      console.log(`Transaction ${transaction.tx_id} confirmed`);
    }
    
    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// =====================================================
// 12. BACKGROUND SERVICES
// =====================================================

class BackgroundServices {
  constructor() {
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;

    // Price updates every 5 minutes
    this.priceUpdateInterval = setInterval(this.updatePrices.bind(this), 5 * 60 * 1000);
    
    // Plan maturity check every hour
    this.maturityCheckInterval = setInterval(this.checkPlanMaturity.bind(this), 60 * 60 * 1000);
    
    // Cleanup old transactions every day
    this.cleanupInterval = setInterval(this.cleanupOldData.bind(this), 24 * 60 * 60 * 1000);
    
    console.log('Background services started');
  }

  stop() {
    if (!this.isRunning) return;
    this.isRunning = false;

    clearInterval(this.priceUpdateInterval);
    clearInterval(this.maturityCheckInterval);
    clearInterval(this.cleanupInterval);
    
    console.log('Background services stopped');
  }

  async updatePrices() {
    try {
      // In production, fetch real STX price from CoinGecko or similar
      console.log('Updating STX price...');
      // Implementation would go here
    } catch (error) {
      console.error('Error updating prices:', error);
    }
  }

  async checkPlanMaturity() {
    try {
      const currentBlock = await getCurrentBlockHeight();
      const maturedPlans = await SavingsPlan.find({
        isActive: true,
        maturityBlock: { $lte: currentBlock }
      });

      for (const plan of maturedPlans) {
        plan.status = 'completed';
        await plan.save();
        console.log(`Plan ${plan.planId} has matured`);
      }
    } catch (error) {
      console.error('Error checking plan maturity:', error);
    }
  }

  async cleanupOldData() {
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      // Remove old failed transactions
      await Transaction.deleteMany({
        status: 'failed',
        timestamp: { $lt: thirtyDaysAgo }
      });

      console.log('Cleaned up old data');
    } catch (error) {
      console.error('Error cleaning up old data:', error);
    }
  }
}

const backgroundServices = new BackgroundServices();

// =====================================================
// 13. ADDITIONAL API ENDPOINTS
// =====================================================

// Get plan details with full history
app.get('/api/plans/:planId', async (req, res) => {
  try {
    const { planId } = req.params;
    const { userAddress } = req.query;

    const plan = await SavingsPlan.findOne({ 
      planId: parseInt(planId),
      userAddress 
    });

    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    // Get transaction history for this plan
    const transactions = await Transaction.find({ 
      planId: parseInt(planId) 
    }).sort({ timestamp: -1 });

    // Calculate performance metrics
    const totalDeposited = transactions
      .filter(tx => tx.type === 'deposit' && tx.status === 'confirmed')
      .reduce((sum, tx) => sum + tx.amount, 0);

    const avgDepositAmount = totalDeposited / plan.totalDeposits;
    const projectedTotal = plan.amountPerDeposit * plan.durationMonths * 
      (plan.frequency === 'daily' ? 30 : plan.frequency === 'weekly' ? 4 : 1);

    res.json({
      plan: {
        ...plan.toObject(),
        currentBalanceUSD: stxToUsd(plan.currentBalance),
        projectedTotalUSD: stxToUsd(projectedTotal)
      },
      transactions: transactions.map(tx => ({
        ...tx.toObject(),
        amountUSD: stxToUsd(tx.amount)
      })),
      metrics: {
        totalDeposited,
        avgDepositAmount,
        projectedTotal,
        completionPercentage: Math.min(100, (plan.totalDeposits / (plan.durationMonths * (plan.frequency === 'daily' ? 30 : plan.frequency === 'weekly' ? 4 : 1))) * 100),
        daysActive: Math.floor((new Date() - plan.createdAt) / (1000 * 60 * 60 * 24))
      }
    });
  } catch (error) {
    console.error('Error fetching plan details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update plan settings
app.put('/api/plans/:planId', async (req, res) => {
  try {
    const { planId } = req.params;
    const { userAddress, frequency, amountPerDeposit } = req.body;

    const plan = await SavingsPlan.findOne({ 
      planId: parseInt(planId),
      userAddress,
      isActive: true 
    });

    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    // Validate updates
    if (frequency && !['daily', 'weekly', 'monthly'].includes(frequency)) {
      return res.status(400).json({ error: 'Invalid frequency' });
    }

    if (amountPerDeposit && amountPerDeposit <= 0) {
      return res.status(400).json({ error: 'Invalid deposit amount' });
    }

    // Update plan
    if (frequency) {
      plan.frequency = frequency;
      plan.nextDepositDate = getNextDepositDate(frequency);
    }
    
    if (amountPerDeposit) {
      plan.amountPerDeposit = amountPerDeposit;
    }

    await plan.save();

    res.json({ 
      success: true, 
      plan: plan.toObject() 
    });
  } catch (error) {
    console.error('Error updating plan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Pause/Resume plan
app.post('/api/plans/:planId/toggle', async (req, res) => {
  try {
    const { planId } = req.params;
    const { userAddress } = req.body;

    const plan = await SavingsPlan.findOne({ 
      planId: parseInt(planId),
      userAddress 
    });

    if (!plan) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    plan.status = plan.status === 'active' ? 'paused' : 'active';
    plan.isActive = plan.status === 'active';
    
    if (plan.status === 'active') {
      plan.nextDepositDate = getNextDepositDate(plan.frequency);
    }

    await plan.save();

    res.json({ 
      success: true, 
      status: plan.status,
      plan: plan.toObject() 
    });
  } catch (error) {
    console.error('Error toggling plan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user notifications
app.get('/api/users/:address/notifications', async (req, res) => {
  try {
    const { address } = req.params;

    // Get plans that need attention
    const now = new Date();
    const duePlans = await SavingsPlan.find({
      userAddress: address,
      isActive: true,
      nextDepositDate: { $lte: now }
    });

    const maturedPlans = await SavingsPlan.find({
      userAddress: address,
      status: 'completed'
    });

    const notifications = [
      ...duePlans.map(plan => ({
        id: `deposit-due-${plan.planId}`,
        type: 'deposit_due',
        title: 'Deposit Due',
        message: `Your ${plan.frequency} deposit of ${plan.amountPerDeposit} STX is due`,
        planId: plan.planId,
        createdAt: plan.nextDepositDate,
        priority: 'high'
      })),
      ...maturedPlans.map(plan => ({
        id: `plan-matured-${plan.planId}`,
        type: 'plan_matured',
        title: 'Plan Completed',
        message: `Your savings plan has matured! ${plan.currentBalance} STX is ready for withdrawal`,
        planId: plan.planId,
        createdAt: plan.createdAt,
        priority: 'high'
      }))
    ];

    res.json({ notifications });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Export user data (GDPR compliance)
app.get('/api/users/:address/export', async (req, res) => {
  try {
    const { address } = req.params;

    const user = await User.findOne({ walletAddress: address });
    const plans = await SavingsPlan.find({ userAddress: address });
    const transactions = await Transaction.find({ userAddress: address });

    const exportData = {
      user: user?.toObject(),
      plans: plans.map(p => p.toObject()),
      transactions: transactions.map(t => t.toObject()),
      exportedAt: new Date().toISOString()
    };

    res.json(exportData);
  } catch (error) {
    console.error('Error exporting user data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =====================================================
// 14. ADMIN ENDPOINTS (Protected)
// =====================================================

// Simple admin middleware (in production, use proper auth)
const adminAuth = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// Admin dashboard stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    const now = new Date();
    const startOfDay = new Date(now.setHours(0, 0, 0, 0));
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const stats = {
      users: {
        total: await User.countDocuments(),
        newToday: await User.countDocuments({ createdAt: { $gte: startOfDay } }),
        newThisMonth: await User.countDocuments({ createdAt: { $gte: startOfMonth } })
      },
      plans: {
        total: await SavingsPlan.countDocuments(),
        active: await SavingsPlan.countDocuments({ isActive: true }),
        completed: await SavingsPlan.countDocuments({ status: 'completed' }),
        paused: await SavingsPlan.countDocuments({ status: 'paused' })
      },
      transactions: {
        total: await Transaction.countDocuments(),
        pending: await Transaction.countDocuments({ status: 'pending' }),
        confirmed: await Transaction.countDocuments({ status: 'confirmed' }),
        failed: await Transaction.countDocuments({ status: 'failed' })
      }
    };

    // Calculate total value locked
    const tvlResult = await SavingsPlan.aggregate([
      { $match: { isActive: true } },
      { $group: { _id: null, total: { $sum: '$currentBalance' } } }
    ]);
    
    stats.tvl = {
      stx: tvlResult[0]?.total || 0,
      usd: stxToUsd(tvlResult[0]?.total || 0)
    };

    res.json(stats);
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =====================================================
// 15. GRACEFUL SHUTDOWN
// =====================================================

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  
  backgroundServices.stop();
  
  try {
    await mongoose.connection.close();
    console.log('Database connection closed');
  } catch (error) {
    console.error('Error closing database connection:', error);
  }
  
  process.exit(0);
}

// Start background services
backgroundServices.start();

// =====================================================
// 16. PACKAGE.JSON DEPENDENCIES
// =====================================================

/*
{
  "name": "arche-vault-backend",
  "version": "1.0.0",
  "description": "Backend for Arche Vault - Automated Bitcoin Savings Platform",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest",
    "lint": "eslint .",
    "deploy": "pm2 start ecosystem.config.js"
  },
  "dependencies": {
    "@stacks/api": "^7.0.0",
    "@stacks/network": "^6.0.0",
    "@stacks/transactions": "^6.0.0",
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "dotenv": "^16.3.1",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "validator": "^13.11.0",
    "morgan": "^1.10.0",
    "compression": "^1.7.4",
    "winston": "^3.10.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.4",
    "supertest": "^6.3.3",
    "eslint": "^8.48.0"
  },
  "engines": {
    "node": ">=16.0.0"
  }
}
*/

// =====================================================
// 17. ENVIRONMENT VARIABLES (.env)
// =====================================================

/*
# Server Configuration
NODE_ENV=development
PORT=3001
FRONTEND_URL=http://localhost:3000

# Database
MONGODB_URI=mongodb://localhost:27017/arche-vault

# Stacks Network
STACKS_NETWORK=testnet
CONTRACT_ADDRESS=ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM
CONTRACT_NAME=arche-vault

# Security
ADMIN_KEY=your-secure-admin-key-here
JWT_SECRET=your-jwt-secret-here

# External APIs
COINGECKO_API_KEY=your-coingecko-api-key
WEBHOOK_SECRET=your-webhook-secret

# Logging
LOG_LEVEL=info
*/

// =====================================================
// 18. DOCKER CONFIGURATION
// =====================================================

/*
# Dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3001

USER node

CMD ["npm", "start"]
*/

/*
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/arche-vault
    depends_on:
      - mongo
    restart: unless-stopped

  mongo:
    image: mongo:6.0
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - app
    restart: unless-stopped

volumes:
  mongo_data:
*/

console.log('Arche Vault Backend System Loaded Successfully!');
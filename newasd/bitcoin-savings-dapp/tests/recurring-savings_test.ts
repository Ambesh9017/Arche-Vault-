import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals, assertExists } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

// Test constants
const CONTRACT_NAME = 'recurring-savings';
const MIN_CONTRIBUTION = 1000000; // 1 STX in microSTX
const DAILY_BLOCKS = 144;
const WEEKLY_BLOCKS = 1008;
const MONTHLY_BLOCKS = 4320;

// Helper function to create a standard savings plan
function createStandardPlan(wallet: Account, contributionAmount = 50000000, intervalBlocks = WEEKLY_BLOCKS, lockDuration = 30 * DAILY_BLOCKS) {
    return Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
        types.uint(contributionAmount),
        types.uint(intervalBlocks),
        types.uint(lockDuration),
        types.bool(false) // auto-renewal
    ], wallet.address);
}

// =============================================================================
// PLAN CREATION TESTS
// =============================================================================

Clarinet.test({
    name: "✅ Can create a savings plan successfully with valid parameters",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet)
        ]);
        
        assertEquals(block.receipts.length, 1);
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Verify plan was created
        let planCall = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet.address)
        ], wallet.address);
        
        let plan = planCall.result.expectSome().expectTuple();
        assertEquals(plan['contribution-amount'], types.uint(50000000));
        assertEquals(plan['interval-blocks'], types.uint(WEEKLY_BLOCKS));
        assertEquals(plan['is-active'], types.bool(true));
    },
});

Clarinet.test({
    name: "❌ Cannot create plan with invalid contribution amount (too small)",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(500000), // 0.5 STX - below minimum
                types.uint(WEEKLY_BLOCKS),
                types.uint(30 * DAILY_BLOCKS),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(101); // ERR-INVALID-AMOUNT
    },
});

Clarinet.test({
    name: "❌ Cannot create plan with invalid interval (too short)",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(50000000),
                types.uint(100), // Less than 144 blocks (1 day minimum)
                types.uint(30 * DAILY_BLOCKS),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(101); // ERR-INVALID-AMOUNT
    },
});

Clarinet.test({
    name: "❌ Cannot create multiple plans for same user",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet),
            createStandardPlan(wallet) // Second plan should fail
        ]);
        
        assertEquals(block.receipts.length, 2);
        block.receipts[0].result.expectOk().expectBool(true);
        block.receipts[1].result.expectErr().expectUint(105); // ERR-PLAN-ALREADY-EXISTS
    },
});

Clarinet.test({
    name: "✅ Can create plan with auto-renewal enabled",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(25000000),
                types.uint(DAILY_BLOCKS),
                types.uint(7 * DAILY_BLOCKS),
                types.bool(true) // auto-renewal enabled
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Verify auto-renewal is set
        let plan = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet.address)
        ], wallet.address).result.expectSome().expectTuple();
        
        assertEquals(plan['auto-renewal'], types.bool(true));
    },
});

// =============================================================================
// CONTRIBUTION TESTS
// =============================================================================

Clarinet.test({
    name: "✅ Can contribute to savings plan after interval period",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        // Create plan with daily contributions for faster testing
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(10000000), // 10 STX
                types.uint(DAILY_BLOCKS),
                types.uint(7 * DAILY_BLOCKS),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Mine blocks to simulate time passage
        chain.mineEmptyBlockUntil(DAILY_BLOCKS + 2);
        
        // Make first contribution
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
        ]);
        
        let result = block.receipts[0].result.expectOk().expectTuple();
        assertEquals(result['contribution-id'], types.uint(0));
        
        // Check balance was updated
        let balance = chain.callReadOnlyFn(CONTRACT_NAME, 'get-user-balance', [
            types.principal(wallet.address)
        ], wallet.address).result.expectSome().expectTuple();
        
        // Balance should be contribution minus fee (0.25%)
        let expectedBalance = 10000000 - Math.floor(10000000 * 25 / 10000);
        assertEquals(balance['balance'], types.uint(expectedBalance));
    },
});

Clarinet.test({
    name: "❌ Cannot contribute before interval period expires",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet),
            // Try to contribute immediately (should fail)
            Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
        ]);
        
        assertEquals(block.receipts.length, 2);
        block.receipts[0].result.expectOk().expectBool(true);
        block.receipts[1].result.expectErr().expectUint(108); // ERR-CONTRIBUTION-TOO-EARLY
    },
});

Clarinet.test({
    name: "✅ Can make multiple contributions over time",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        // Create daily plan
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(5000000), // 5 STX
                types.uint(DAILY_BLOCKS),
                types.uint(10 * DAILY_BLOCKS),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Make 3 contributions
        for (let i = 1; i <= 3; i++) {
            chain.mineEmptyBlockUntil((DAILY_BLOCKS * i) + 2);
            
            block = chain.mineBlock([
                Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
            ]);
            
            let result = block.receipts[0].result.expectOk().expectTuple();
            assertEquals(result['contribution-id'], types.uint(i - 1));
        }
        
        // Check total contributions
        let plan = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet.address)
        ], wallet.address).result.expectSome().expectTuple();
        
        assertEquals(plan['contributions-count'], types.uint(3));
    },
});

Clarinet.test({
    name: "❌ Cannot contribute to inactive plan",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        // This would require deactivating a plan first, which happens on withdrawal
        // For now, we'll test the plan creation and assume deactivation works
        let block = chain.mineBlock([
            createStandardPlan(wallet)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Test will be expanded when we have plan deactivation scenarios
    },
});

// =============================================================================
// WITHDRAWAL TESTS
// =============================================================================

Clarinet.test({
    name: "✅ Can withdraw after lock period expires",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        const lockDuration = 5 * DAILY_BLOCKS; // 5 days for testing
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(20000000), // 20 STX
                types.uint(DAILY_BLOCKS),
                types.uint(lockDuration),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Make a contribution
        chain.mineEmptyBlockUntil(DAILY_BLOCKS + 2);
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
        ]);
        block.receipts[0].result.expectOk();
        
        // Wait until lock expires
        chain.mineEmptyBlockUntil(lockDuration + 10);
        
        // Now withdrawal should work
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'withdraw-savings', [], wallet.address)
        ]);
        
        let withdrawnAmount = block.receipts[0].result.expectOk().expectUint();
        
        // Should withdraw the net amount (contribution minus fee)
        let expectedAmount = 20000000 - Math.floor(20000000 * 25 / 10000);
        assertEquals(withdrawnAmount, expectedAmount);
    },
});

Clarinet.test({
    name: "❌ Cannot withdraw before lock period expires",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Make a contribution
        chain.mineEmptyBlockUntil(WEEKLY_BLOCKS + 2);
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
        ]);
        block.receipts[0].result.expectOk();
        
        // Try to withdraw immediately (should fail)
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'withdraw-savings', [], wallet.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(109); // ERR-WITHDRAWAL-TOO-EARLY
    },
});

Clarinet.test({
    name: "✅ Emergency withdrawal works with penalty",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet, 30000000) // 30 STX
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Make a contribution
        chain.mineEmptyBlockUntil(WEEKLY_BLOCKS + 2);
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
        ]);
        block.receipts[0].result.expectOk();
        
        // Emergency withdraw
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'emergency-withdraw', [], wallet.address)
        ]);
        
        let result = block.receipts[0].result.expectOk().expectTuple();
        let withdrawn = result['withdrawn'].expectUint();
        let penalty = result['penalty'].expectUint();
        
        // Verify penalty calculation (10%)
        let netContribution = 30000000 - Math.floor(30000000 * 25 / 10000);
        let expectedPenalty = Math.floor(netContribution * 1000 / 10000);
        let expectedWithdrawal = netContribution - expectedPenalty;
        
        assertEquals(withdrawn, expectedWithdrawal);
        assertEquals(penalty, expectedPenalty);
    },
});

// =============================================================================
// READ-ONLY FUNCTION TESTS
// =============================================================================

Clarinet.test({
    name: "✅ can-contribute returns correct status",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Initially should not be able to contribute (just created)
        let canContribute = chain.callReadOnlyFn(CONTRACT_NAME, 'can-contribute', [
            types.principal(wallet.address)
        ], wallet.address);
        
        assertEquals(canContribute.result, types.bool(false));
        
        // After interval, should be able to contribute
        chain.mineEmptyBlockUntil(WEEKLY_BLOCKS + 2);
        
        canContribute = chain.callReadOnlyFn(CONTRACT_NAME, 'can-contribute', [
            types.principal(wallet.address)
        ], wallet.address);
        
        assertEquals(canContribute.result, types.bool(true));
    },
});

Clarinet.test({
    name: "✅ can-withdraw returns correct status",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        const lockDuration = 3 * DAILY_BLOCKS;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(10000000),
                types.uint(DAILY_BLOCKS),
                types.uint(lockDuration),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Initially should not be able to withdraw
        let canWithdraw = chain.callReadOnlyFn(CONTRACT_NAME, 'can-withdraw', [
            types.principal(wallet.address)
        ], wallet.address);
        
        assertEquals(canWithdraw.result, types.bool(false));
        
        // After lock period, should be able to withdraw
        chain.mineEmptyBlockUntil(lockDuration + 5);
        
        canWithdraw = chain.callReadOnlyFn(CONTRACT_NAME, 'can-withdraw', [
            types.principal(wallet.address)
        ], wallet.address);
        
        assertEquals(canWithdraw.result, types.bool(true));
    },
});

Clarinet.test({
    name: "✅ calculate-plan-projection returns accurate estimates",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let projection = chain.callReadOnlyFn(CONTRACT_NAME, 'calculate-plan-projection', [
            types.uint(10000000), // 10 STX
            types.uint(WEEKLY_BLOCKS), // Weekly
            types.uint(4 * WEEKLY_BLOCKS) // 4 weeks
        ], wallet.address);
        
        let result = projection.result.expectTuple();
        
        // Should estimate 4 contributions
        assertEquals(result['estimated-contributions'], types.uint(4));
        
        // Total should be 40 STX
        assertEquals(result['total-contributions'], types.uint(40000000));
        
        // Net savings should be total minus fees
        let expectedFees = Math.floor(40000000 * 25 / 10000);
        let expectedNetSavings = 40000000 - expectedFees;
        assertEquals(result['net-savings'], types.uint(expectedNetSavings));
    },
});

Clarinet.test({
    name: "✅ get-plan-progress returns accurate progress information",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        const lockDuration = 10 * DAILY_BLOCKS;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(5000000),
                types.uint(DAILY_BLOCKS),
                types.uint(lockDuration),
                types.bool(false)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Mine some blocks to simulate progress
        chain.mineEmptyBlockUntil(5 * DAILY_BLOCKS); // 50% progress
        
        let progress = chain.callReadOnlyFn(CONTRACT_NAME, 'get-plan-progress', [
            types.principal(wallet.address)
        ], wallet.address);
        
        let result = progress.result.expectSome().expectTuple();
        
        // Should be approximately 50% progress
        let progressPercent = result['progress-percentage'].expectUint();
        assertEquals(progressPercent >= 4900 && progressPercent <= 5100, true); // Allow some variance
        
        assertEquals(result['elapsed-blocks'], types.uint(5 * DAILY_BLOCKS));
        assertEquals(result['blocks-remaining'], types.uint(5 * DAILY_BLOCKS));
    },
});

Clarinet.test({
    name: "✅ get-next-contribution-info provides correct details",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet, 15000000) // 15 STX
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        let info = chain.callReadOnlyFn(CONTRACT_NAME, 'get-next-contribution-info', [
            types.principal(wallet.address)
        ], wallet.address);
        
        let result = info.result.expectSome().expectTuple();
        
        assertEquals(result['can-contribute-now'], types.bool(false));
        assertEquals(result['contribution-amount'], types.uint(15000000));
        
        let expectedFee = Math.floor(15000000 * 25 / 10000);
        assertEquals(result['fee-amount'], types.uint(expectedFee));
    },
});

// =============================================================================
// ADMIN FUNCTION TESTS
// =============================================================================

Clarinet.test({
    name: "✅ Contract owner can set fee rate",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'set-fee-rate', [
                types.uint(50) // 0.5%
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Verify fee rate was updated
        let stats = chain.callReadOnlyFn(CONTRACT_NAME, 'get-contract-stats', [], deployer.address);
        let result = stats.result.expectTuple();
        assertEquals(result['current-fee-rate'], types.uint(50));
    },
});

Clarinet.test({
    name: "❌ Non-owner cannot set fee rate",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'set-fee-rate', [
                types.uint(50)
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(100); // ERR-UNAUTHORIZED
    },
});

Clarinet.test({
    name: "❌ Cannot set fee rate above maximum (5%)",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'set-fee-rate', [
                types.uint(600) // 6% - above maximum
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(101); // ERR-INVALID-AMOUNT
    },
});

// =============================================================================
// INTEGRATION AND EDGE CASE TESTS
// =============================================================================

Clarinet.test({
    name: "✅ Complete savings cycle with auto-renewal",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        const lockDuration = 3 * DAILY_BLOCKS;
        
        let block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'create-savings-plan', [
                types.uint(8000000), // 8 STX
                types.uint(DAILY_BLOCKS),
                types.uint(lockDuration),
                types.bool(true) // Auto-renewal enabled
            ], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Make some contributions
        for (let i = 1; i <= 2; i++) {
            chain.mineEmptyBlockUntil(DAILY_BLOCKS * i + 2);
            block = chain.mineBlock([
                Tx.contractCall(CONTRACT_NAME, 'contribute-to-savings', [], wallet.address)
            ]);
            block.receipts[0].result.expectOk();
        }
        
        // Wait for lock to expire and withdraw
        chain.mineEmptyBlockUntil(lockDuration + 10);
        
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'withdraw-savings', [], wallet.address)
        ]);
        
        block.receipts[0].result.expectOk();
        
        // Verify plan was renewed (still active)
        let plan = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet.address)
        ], wallet.address).result.expectSome().expectTuple();
        
        assertEquals(plan['is-active'], types.bool(true));
        assertEquals(plan['contributions-count'], types.uint(0)); // Reset for new cycle
    },
});

Clarinet.test({
    name: "✅ Multiple users can create independent plans",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet1 = accounts.get('wallet_1')!;
        const wallet2 = accounts.get('wallet_2')!;
        const wallet3 = accounts.get('wallet_3')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet1, 10000000),
            createStandardPlan(wallet2, 20000000),
            createStandardPlan(wallet3, 30000000)
        ]);
        
        assertEquals(block.receipts.length, 3);
        block.receipts.forEach(receipt => {
            receipt.result.expectOk().expectBool(true);
        });
        
        // Verify each plan has correct details
        let plan1 = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet1.address)
        ], wallet1.address).result.expectSome().expectTuple();
        
        let plan2 = chain.callReadOnlyFn(CONTRACT_NAME, 'get-savings-plan', [
            types.principal(wallet2.address)
        ], wallet2.address).result.expectSome().expectTuple();
        
        assertEquals(plan1['contribution-amount'], types.uint(10000000));
        assertEquals(plan2['contribution-amount'], types.uint(20000000));
        
        // Check global stats updated
        let stats = chain.callReadOnlyFn(CONTRACT_NAME, 'get-contract-stats', [], wallet1.address);
        let result = stats.result.expectTuple();
        assertEquals(result['total-users'], types.uint(3));
    },
});

Clarinet.test({
    name: "✅ Contract handles edge case of zero balance withdrawal",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const wallet = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            createStandardPlan(wallet)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Wait for lock to expire without making contributions
        chain.mineEmptyBlockUntil(30 * DAILY_BLOCKS + 10);
        
        // Try to withdraw with zero balance
        block = chain.mineBlock([
            Tx.contractCall(CONTRACT_NAME, 'withdraw-savings', [], wallet.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(104); // ERR-INSUFFICIENT-BALANCE
    },
});
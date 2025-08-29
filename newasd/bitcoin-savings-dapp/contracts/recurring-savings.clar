;; Bitcoin-Backed Recurring Savings Plan Smart Contract
;; Built on Stacks blockchain using Clarity
;; Version: 1.0.0

;; =============================================================================
;; CONSTANTS AND ERROR CODES
;; =============================================================================

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INVALID-AMOUNT (err u101))
(define-constant ERR-PLAN-NOT-FOUND (err u102))
(define-constant ERR-PLAN-LOCKED (err u103))
(define-constant ERR-INSUFFICIENT-BALANCE (err u104))
(define-constant ERR-PLAN-ALREADY-EXISTS (err u105))
(define-constant ERR-INVALID-INTERVAL (err u106))
(define-constant ERR-PLAN-INACTIVE (err u107))
(define-constant ERR-CONTRIBUTION-TOO-EARLY (err u108))
(define-constant ERR-WITHDRAWAL-TOO-EARLY (err u109))

;; Minimum values for safety
(define-constant MIN-CONTRIBUTION u1000000) ;; 1 STX minimum
(define-constant MIN-INTERVAL u144) ;; 1 day minimum (144 blocks)
(define-constant MIN-LOCK-DURATION u144) ;; 1 day minimum lock

;; =============================================================================
;; DATA STRUCTURES
;; =============================================================================

;; Define savings plan structure
(define-map savings-plans
  { user: principal }
  {
    total-amount: uint,
    contribution-amount: uint,
    interval-blocks: uint,
    start-block: uint,
    lock-duration-blocks: uint,
    total-contributed: uint,
    contributions-count: uint,
    last-contribution-block: uint,
    expected-end-block: uint,
    is-active: bool,
    auto-renewal: bool
  }
)

;; Track individual user balances in the contract
(define-map user-balances 
  { user: principal } 
  { 
    balance: uint,
    locked-until-block: uint
  }
)

;; Track contribution history for analytics
(define-map contribution-history
  { user: principal, contribution-id: uint }
  {
    amount: uint,
    block-height: uint,
    timestamp: uint
  }
)

;; Global contract stats
(define-data-var total-users uint u0)
(define-data-var total-volume uint u0)
(define-data-var contract-fee-rate uint u25) ;; 0.25% fee (25 basis points)

;; =============================================================================
;; PRIVATE HELPER FUNCTIONS
;; =============================================================================

(define-private (is-valid-plan-params (contribution-amount uint) (interval-blocks uint) (lock-duration-blocks uint))
  (and 
    (>= contribution-amount MIN-CONTRIBUTION)
    (>= interval-blocks MIN-INTERVAL)
    (>= lock-duration-blocks MIN-LOCK-DURATION)
  )
)

(define-private (calculate-fee (amount uint))
  (/ (* amount (var-get contract-fee-rate)) u10000)
)

(define-private (get-next-contribution-id (user principal))
  (match (map-get? savings-plans { user: user })
    plan (get contributions-count plan)
    u0
  )
)

;; =============================================================================
;; PUBLIC FUNCTIONS - CORE FUNCTIONALITY
;; =============================================================================

;; Create a new recurring savings plan
(define-public (create-savings-plan 
  (contribution-amount uint)
  (interval-blocks uint)
  (lock-duration-blocks uint)
  (auto-renewal bool))
  (let
    (
      (user tx-sender)
      (start-block block-height)
      (expected-contributions (/ lock-duration-blocks interval-blocks))
      (expected-total (* contribution-amount expected-contributions))
    )
    ;; Validation checks
    (asserts! (is-none (map-get? savings-plans { user: user })) ERR-PLAN-ALREADY-EXISTS)
    (asserts! (is-valid-plan-params contribution-amount interval-blocks lock-duration-blocks) ERR-INVALID-AMOUNT)
    
    ;; Create the savings plan
    (map-set savings-plans
      { user: user }
      {
        total-amount: expected-total,
        contribution-amount: contribution-amount,
        interval-blocks: interval-blocks,
        start-block: start-block,
        lock-duration-blocks: lock-duration-blocks,
        total-contributed: u0,
        contributions-count: u0,
        last-contribution-block: start-block,
        expected-end-block: (+ start-block lock-duration-blocks),
        is-active: true,
        auto-renewal: auto-renewal
      }
    )
    
    ;; Initialize user balance
    (map-set user-balances
      { user: user }
      { 
        balance: u0,
        locked-until-block: (+ start-block lock-duration-blocks)
      }
    )
    
    ;; Update global stats
    (var-set total-users (+ (var-get total-users) u1))
    
    (ok true)
  )
)

;; Make a contribution to the savings plan
(define-public (contribute-to-savings)
  (let
    (
      (user tx-sender)
      (plan (unwrap! (map-get? savings-plans { user: user }) ERR-PLAN-NOT-FOUND))
      (current-balance (default-to { balance: u0, locked-until-block: u0 } 
                                  (map-get? user-balances { user: user })))
      (contribution-amount (get contribution-amount plan))
      (fee-amount (calculate-fee contribution-amount))
      (net-amount (- contribution-amount fee-amount))
      (next-contribution-id (get contributions-count plan))
    )
    ;; Validation checks
    (asserts! (get is-active plan) ERR-PLAN-INACTIVE)
    (asserts! (>= (- block-height (get last-contribution-block plan)) (get interval-blocks plan)) 
              ERR-CONTRIBUTION-TOO-EARLY)
    
    ;; Transfer STX from user to contract (including fee)
    (try! (stx-transfer? contribution-amount user (as-contract tx-sender)))
    
    ;; Update savings plan
    (map-set savings-plans
      { user: user }
      (merge plan
        {
          total-contributed: (+ (get total-contributed plan) net-amount),
          contributions-count: (+ next-contribution-id u1),
          last-contribution-block: block-height
        }
      )
    )
    
    ;; Update user balance (excluding fee)
    (map-set user-balances
      { user: user }
      (merge current-balance
        { balance: (+ (get balance current-balance) net-amount) }
      )
    )
    
    ;; Record contribution history
    (map-set contribution-history
      { user: user, contribution-id: next-contribution-id }
      {
        amount: net-amount,
        block-height: block-height,
        timestamp: stacks-block-height ;; Using stacks block height as timestamp proxy
      }
    )
    
    ;; Update global volume
    (var-set total-volume (+ (var-get total-volume) contribution-amount))
    
    (ok {
      contribution-id: next-contribution-id,
      amount: net-amount,
      fee: fee-amount,
      new-balance: (+ (get balance current-balance) net-amount)
    })
  )
)

;; Withdraw savings after lock period expires
(define-public (withdraw-savings)
  (let
    (
      (user tx-sender)
      (plan (unwrap! (map-get? savings-plans { user: user }) ERR-PLAN-NOT-FOUND))
      (user-balance (unwrap! (map-get? user-balances { user: user }) ERR-INSUFFICIENT-BALANCE))
      (unlock-block (get locked-until-block user-balance))
      (withdrawal-amount (get balance user-balance))
    )
    ;; Validation checks
    (asserts! (>= block-height unlock-block) ERR-WITHDRAWAL-TOO-EARLY)
    (asserts! (> withdrawal-amount u0) ERR-INSUFFICIENT-BALANCE)
    
    ;; Transfer balance back to user
    (try! (as-contract (stx-transfer? withdrawal-amount tx-sender user)))
    
    ;; Reset user balance
    (map-set user-balances 
      { user: user } 
      { balance: u0, locked-until-block: u0 }
    )
    
    ;; Handle plan renewal or deactivation
    (if (get auto-renewal plan)
      ;; Renew the plan for another cycle
      (map-set savings-plans
        { user: user }
        (merge plan {
          start-block: block-height,
          expected-end-block: (+ block-height (get lock-duration-blocks plan)),
          last-contribution-block: block-height,
          total-contributed: u0,
          contributions-count: u0
        })
      )
      ;; Deactivate the plan
      (map-set savings-plans
        { user: user }
        (merge plan { is-active: false })
      )
    )
    
    (ok withdrawal-amount)
  )
)

;; Emergency withdrawal (with penalty)
(define-public (emergency-withdraw)
  (let
    (
      (user tx-sender)
      (plan (unwrap! (map-get? savings-plans { user: user }) ERR-PLAN-NOT-FOUND))
      (user-balance (unwrap! (map-get? user-balances { user: user }) ERR-INSUFFICIENT-BALANCE))
      (balance-amount (get balance user-balance))
      (penalty-rate u1000) ;; 10% penalty
      (penalty-amount (/ (* balance-amount penalty-rate) u10000))
      (withdrawal-amount (- balance-amount penalty-amount))
    )
    ;; Validation checks
    (asserts! (> balance-amount u0) ERR-INSUFFICIENT-BALANCE)
    (asserts! (get is-active plan) ERR-PLAN-INACTIVE)
    
    ;; Transfer reduced amount to user (penalty stays in contract)
    (try! (as-contract (stx-transfer? withdrawal-amount tx-sender user)))
    
    ;; Reset user balance and deactivate plan
    (map-set user-balances 
      { user: user } 
      { balance: u0, locked-until-block: u0 }
    )
    
    (map-set savings-plans
      { user: user }
      (merge plan { is-active: false })
    )
    
    (ok {
      withdrawn: withdrawal-amount,
      penalty: penalty-amount,
      penalty-rate: penalty-rate
    })
  )
)

;; =============================================================================
;; ADMIN FUNCTIONS
;; =============================================================================

;; Update contract fee rate (only owner)
(define-public (set-fee-rate (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (asserts! (<= new-rate u500) ERR-INVALID-AMOUNT) ;; Max 5% fee
    (var-set contract-fee-rate new-rate)
    (ok true)
  )
)

;; Withdraw accumulated fees (only owner)
(define-public (withdraw-fees (amount uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (try! (as-contract (stx-transfer? amount tx-sender CONTRACT-OWNER)))
    (ok amount)
  )
)

;; =============================================================================
;; READ-ONLY FUNCTIONS
;; =============================================================================

;; Get savings plan details
(define-read-only (get-savings-plan (user principal))
  (map-get? savings-plans { user: user })
)

;; Get user balance information
(define-read-only (get-user-balance (user principal))
  (map-get? user-balances { user: user })
)

;; Check if user can make a contribution
(define-read-only (can-contribute (user principal))
  (match (map-get? savings-plans { user: user })
    plan (and 
      (get is-active plan)
      (>= (- block-height (get last-contribution-block plan)) (get interval-blocks plan))
    )
    false
  )
)

;; Check if user can withdraw
(define-read-only (can-withdraw (user principal))
  (match (map-get? user-balances { user: user })
    balance (>= block-height (get locked-until-block balance))
    false
  )
)

;; Get contribution history
(define-read-only (get-contribution-history (user principal) (contribution-id uint))
  (map-get? contribution-history { user: user, contribution-id: contribution-id })
)

;; Get contract statistics
(define-read-only (get-contract-stats)
  {
    total-users: (var-get total-users),
    total-volume: (var-get total-volume),
    current-fee-rate: (var-get contract-fee-rate)
  }
)

;; Calculate estimated returns for a plan
(define-read-only (calculate-plan-projection (contribution-amount uint) (interval-blocks uint) (lock-duration-blocks uint))
  (let
    (
      (estimated-contributions (/ lock-duration-blocks interval-blocks))
      (total-contributions (* contribution-amount estimated-contributions))
      (total-fees (calculate-fee total-contributions))
      (net-savings (- total-contributions total-fees))
    )
    {
      estimated-contributions: estimated-contributions,
      total-contributions: total-contributions,
      total-fees: total-fees,
      net-savings: net-savings,
      effective-rate: (if (> total-contributions u0) 
                        (/ (* net-savings u10000) total-contributions) 
                        u0)
    }
  )
)

;; Get next contribution details
(define-read-only (get-next-contribution-info (user principal))
  (match (map-get? savings-plans { user: user })
    plan {
      can-contribute-now: (can-contribute user),
      next-contribution-block: (+ (get last-contribution-block plan) (get interval-blocks plan)),
      blocks-until-next: (let ((next-block (+ (get last-contribution-block plan) (get interval-blocks plan))))
                          (if (> next-block block-height) (- next-block block-height) u0)),
      contribution-amount: (get contribution-amount plan),
      fee-amount: (calculate-fee (get contribution-amount plan))
    }
    none
  )
)

;; Get plan progress
(define-read-only (get-plan-progress (user principal))
  (match (map-get? savings-plans { user: user })
    plan (let
      (
        (elapsed-blocks (- block-height (get start-block plan)))
        (total-duration (get lock-duration-blocks plan))
        (progress-percentage (if (> total-duration u0)
                               (min u10000 (/ (* elapsed-blocks u10000) total-duration))
                               u0))
        (expected-contributions-so-far (/ elapsed-blocks (get interval-blocks plan)))
        (actual-contributions (get contributions-count plan))
      )
      {
        elapsed-blocks: elapsed-blocks,
        total-duration: total-duration,
        progress-percentage: progress-percentage,
        expected-contributions: expected-contributions-so-far,
        actual-contributions: actual-contributions,
        contribution-rate: (if (> expected-contributions-so-far u0)
                            (/ (* actual-contributions u10000) expected-contributions-so-far)
                            u0),
        blocks-remaining: (if (> total-duration elapsed-blocks) 
                           (- total-duration elapsed-blocks) 
                           u0)
      }
    )
    none
  )
)
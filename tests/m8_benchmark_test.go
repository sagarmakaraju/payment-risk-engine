package tests

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fs2601/internal/edge"
	"fs2601/internal/fraud"
	"fs2601/internal/gateway"
	"fs2601/internal/ledger"
	"fs2601/internal/reconcile"
	"fs2601/internal/telemetry"
)

// Helper to initialize an isolated gateway environment for testing
func setupTestGateway(t *testing.T, walPath string) (*gateway.PaymentGateway, *ledger.ConservingLedger, *fraud.InMemGraphFraudEngine, *edge.TokenAuthority, *edge.WALStore) {
	_ = os.Remove(walPath)

	coreLedger := ledger.NewConservingLedger()
	fraudSecret := "TEST-FRAUD-SECRET-KEY-2026"
	fraudEngine := fraud.NewInMemGraphFraudEngine(fraudSecret)
	fraudEngine.RegisterTerminal("TERM-TEST-1", "MERCHANT-1")

	tokenAuth, err := edge.NewTokenAuthority()
	if err != nil {
		t.Fatalf("failed to create token authority: %v", err)
	}

	edgeAuth := edge.NewEdgeAuthorizer(tokenAuth.PublicKey(), "TERM-TEST-1")

	walStore, err := edge.NewWALStore(walPath)
	if err != nil {
		t.Fatalf("failed to create WAL store: %v", err)
	}

	reconciler := reconcile.NewReconciler(coreLedger)
	gw := gateway.NewPaymentGateway(coreLedger, fraudEngine, edgeAuth, walStore, reconciler)

	return gw, coreLedger, fraudEngine, tokenAuth, walStore
}

// 1. Concurrency & Zero Double-Spend Gate
// 500 concurrent goroutines attempting to deplete an account with only $1,000 (100,000 cents)
func TestConcurrencyAndZeroDoubleSpend(t *testing.T) {
	walPath := "test_wal_concurrency.log"
	defer os.Remove(walPath)

	gw, coreLedger, _, _, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()
	gw.SetFraudScreeningEnabled(false) // Isolate conserving ledger to test pure 500-goroutine concurrency & double-spend gate

	accountID := "ACC-DRAIN-TEST"
	merchantID := "MERCHANT-DRAIN-DEST"
	initialBalance := int64(100000) // $1,000.00
	transferAmount := int64(1000)   // $10.00 each
	totalGoroutines := 500

	coreLedger.CreateAccount(accountID, initialBalance)
	coreLedger.CreateAccount(merchantID, 0)

	var (
		wg            sync.WaitGroup
		approvedCount int64
		declinedCount int64
		latencies     = make([]time.Duration, totalGoroutines)
	)

	startBarrier := make(chan struct{})

	for i := 0; i < totalGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier // Synchronize simultaneous release

			req := gateway.PaymentRequest{
				IdempotencyKey:  fmt.Sprintf("IDEMP-%d", idx),
				TxID:            fmt.Sprintf("TX-CONC-%d", idx),
				AccountID:       accountID,
				MerchantID:      merchantID,
				TerminalID:      "TERM-TEST-1",
				Amount:          transferAmount,
				DeviceID:        fmt.Sprintf("DEV-%d", idx%10),
				IPAddress:       fmt.Sprintf("192.168.1.%d", idx%50),
				ClientTimestamp: time.Now().Unix(),
			}

			start := time.Now()
			resp := gw.ProcessPayment(req)
			latencies[idx] = time.Since(start)

			if resp.Status == "APPROVED" {
				atomic.AddInt64(&approvedCount, 1)
			} else if resp.Status == "DECLINED" && resp.ReasonCode == telemetry.CodeInsufficientFunds {
				atomic.AddInt64(&declinedCount, 1)
			} else {
				t.Errorf("Unexpected response: %v", resp)
			}
		}(i)
	}

	// Fire all 500 concurrent goroutines simultaneously
	close(startBarrier)
	wg.Wait()

	// Financial Correctness Assertion:
	// Exactly 100 requests of $10 must be approved to deplete $1,000. Exactly 400 must be declined.
	expectedApproved := initialBalance / transferAmount // 100
	expectedDeclined := int64(totalGoroutines) - expectedApproved // 400

	if approvedCount != expectedApproved {
		t.Fatalf("DOUBLE-SPEND VIOLATION: expected %d approvals, got %d", expectedApproved, approvedCount)
	}
	if declinedCount != expectedDeclined {
		t.Fatalf("Declined count mismatch: expected %d, got %d", expectedDeclined, declinedCount)
	}

	// Verify Account Balances
	acc, err := coreLedger.GetAccount(accountID)
	if err != nil {
		t.Fatalf("failed to query source account: %v", err)
	}
	if acc.AvailableBalance != 0 || acc.ReservedBalance != 0 {
		t.Fatalf("Source account balance non-zero: Available=%d, Reserved=%d", acc.AvailableBalance, acc.ReservedBalance)
	}

	merchantAcc, err := coreLedger.GetAccount(merchantID)
	if err != nil {
		t.Fatalf("failed to query merchant account: %v", err)
	}
	if merchantAcc.AvailableBalance != initialBalance {
		t.Fatalf("Merchant balance mismatch: expected %d, got %d", initialBalance, merchantAcc.AvailableBalance)
	}

	// Ledger Double-Entry Conservation Check
	avail, reserved, total, _ := coreLedger.AuditConservation()
	if total != initialBalance {
		t.Fatalf("Double-entry conservation invariant failed: total=%d, initial=%d", total, initialBalance)
	}
	_ = avail
	_ = reserved

	// Latency & Concurrency Metric Check (Target: p99 <= 300ms)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[int(float64(totalGoroutines)*0.50)]
	p90 := latencies[int(float64(totalGoroutines)*0.90)]
	p99 := latencies[int(float64(totalGoroutines)*0.99)]

	t.Logf("=== 500 Concurrent Goroutines Latency Metrics ===")
	t.Logf("p50: %v | p90: %v | p99: %v", p50, p90, p99)

	if p99 > 300*time.Millisecond {
		t.Fatalf("p99 latency %v exceeded maximum threshold 300ms", p99)
	}
}

// 2. Network Partition Simulation & Deterministic Post-Partition Reconciliation
func TestNetworkPartitionAndDeterministicReconciliation(t *testing.T) {
	walPath := "test_wal_partition.log"
	defer os.Remove(walPath)

	gw, coreLedger, fraudEngine, tokenAuth, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()
	fraudEngine.SetVelocityThresholds(50, 100)

	accountID := "ACC-PARTITION-TEST"
	merchantID := "MERCHANT-POS-01"
	initialBalance := int64(200000) // $2,000.00
	coreLedger.CreateAccount(accountID, initialBalance)
	coreLedger.CreateAccount(merchantID, 0)

	// Issue Ed25519 token with max $50 floor limit (5000 cents)
	token, err := tokenAuth.IssueToken(accountID, 5000, 1*time.Hour, "TERM-TEST-1")
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// Phase 1: 10 Online transactions ($10 each = $100)
	for i := 0; i < 10; i++ {
		resp := gw.ProcessPayment(gateway.PaymentRequest{
			TxID:       fmt.Sprintf("TX-ON-%d", i),
			AccountID:  accountID,
			MerchantID: merchantID,
			Amount:     1000,
		})
		if resp.Status != "APPROVED" {
			t.Fatalf("Online payment %d failed: %v", i, resp)
		}
	}

	// Phase 2: Network Partition Cut
	gw.SetNetworkStatus(gateway.NetworkDisconnected)

	// Step A: Attempt payment without offline token -> Should be rejected
	reqNoToken := gateway.PaymentRequest{
		TxID:       "TX-OFF-FAIL-1",
		AccountID:  accountID,
		MerchantID: merchantID,
		Amount:     1000,
	}
	respNoToken := gw.ProcessPayment(reqNoToken)
	if respNoToken.Status != "DECLINED" || respNoToken.ReasonCode != telemetry.CodeOfflineTokenInvalid {
		t.Fatalf("Expected decline without token, got: %v", respNoToken)
	}

	// Step B: Route 50 offline transactions ($1.00 each = 100 cents = $50.00 cumulative floor)
	// We issue fresh tokens or incremental allowance to simulate 50 shoppers
	offlineTokens := make([]*edge.OfflineAuthorizationToken, 50)
	for i := 0; i < 50; i++ {
		tok, err := tokenAuth.IssueToken(accountID, 1000, 1*time.Hour, "TERM-TEST-1")
		if err != nil {
			t.Fatalf("failed to issue offline token %d: %v", i, err)
		}
		offlineTokens[i] = tok
	}

	offlineTxsCommitted := 0
	for i := 0; i < 50; i++ {
		resp := gw.ProcessPayment(gateway.PaymentRequest{
			TxID:            fmt.Sprintf("TX-OFF-%d", i),
			AccountID:       accountID,
			MerchantID:      merchantID,
			Amount:          1000, // $10.00
			OfflineToken:    offlineTokens[i],
			ClientTimestamp: time.Now().Unix() - int64(50-i), // deterministic ordered timestamps
		})

		if resp.Status != "OFFLINE_AUTHORIZED" {
			t.Fatalf("Offline payment %d rejected: %v", i, resp)
		}
		offlineTxsCommitted++
	}

	if offlineTxsCommitted != 50 {
		t.Fatalf("Expected 50 offline authorizations, got %d", offlineTxsCommitted)
	}

	// Step C: Attempt payment exceeding floor limit ($60.00 > $50.00 max) -> Decline
	exceedToken, _ := tokenAuth.IssueToken(accountID, 6000, 1*time.Hour, "TERM-TEST-1")
	respExceed := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:         "TX-OFF-EXCEED",
		AccountID:    accountID,
		MerchantID:   merchantID,
		Amount:       6000,
		OfflineToken: exceedToken,
	})
	if respExceed.Status != "DECLINED" || respExceed.ReasonCode != telemetry.CodeFloorLimitExceeded {
		t.Fatalf("Expected floor limit decline, got: %v", respExceed)
	}

	// Phase 3: Restore Network & Reconcile
	gw.SetNetworkStatus(gateway.NetworkReconnected)

	report, err := gw.TriggerReconciliation()
	if err != nil {
		t.Fatalf("Reconciliation failed: %v", err)
	}

	t.Logf("Reconciliation Report: Processed=%d, Success=%d, Deficit=%d, AmountReconciled=%d",
		report.TotalProcessed, report.SuccessfulCount, report.DeficitCount, report.TotalAmountReconciled)

	if report.SuccessfulCount != 50 {
		t.Fatalf("Expected 50 reconciled transactions, got %d", report.SuccessfulCount)
	}

	// Phase 4: Financial Conservation Invariant Assertion
	// Initial: $2,000.00 (200,000 cents)
	// Online spent: 10 * $10 = $100.00 (10,000 cents)
	// Offline reconciled: 50 * $10 = $500.00 (50,000 cents)
	// Total spent: $600.00 (60,000 cents)
	// Remaining: $1,400.00 (140,000 cents)
	acc, err := coreLedger.GetAccount(accountID)
	if err != nil {
		t.Fatalf("failed to query account: %v", err)
	}
	expectedRemaining := int64(140000)
	if acc.AvailableBalance != expectedRemaining {
		t.Fatalf("Account available balance mismatch: expected %d, got %d", expectedRemaining, acc.AvailableBalance)
	}

	merchantAcc, err := coreLedger.GetAccount(merchantID)
	if err != nil {
		t.Fatalf("failed to query merchant: %v", err)
	}
	expectedMerchant := int64(60000)
	if merchantAcc.AvailableBalance != expectedMerchant {
		t.Fatalf("Merchant balance mismatch: expected %d, got %d", expectedMerchant, merchantAcc.AvailableBalance)
	}

	avail, reserved, total, _ := coreLedger.AuditConservation()
	if total != initialBalance {
		t.Fatalf("Conservation invariant broken: total=%d, initial=%d", total, initialBalance)
	}
	_ = avail
	_ = reserved
	_ = token
}

// 3. Post-Partition Deficit Settlement Handling
func TestPostPartitionDeficitSettlement(t *testing.T) {
	walPath := "test_wal_deficit.log"
	defer os.Remove(walPath)

	gw, coreLedger, _, tokenAuth, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()

	accountID := "ACC-DEFICIT-TEST"
	merchantID := "MERCHANT-DEFICIT"
	coreLedger.CreateAccount(accountID, 3000) // Only $30.00
	coreLedger.CreateAccount(merchantID, 0)

	// Disconnect network
	gw.SetNetworkStatus(gateway.NetworkDisconnected)

	// Execute 2 offline transactions of $20 each = $40 total (exceeds $30 initial balance)
	for i := 1; i <= 2; i++ {
		tok, err := tokenAuth.IssueToken(accountID, 2500, 1*time.Hour, "TERM-TEST-1")
		if err != nil {
			t.Fatalf("token issue error: %v", err)
		}

		resp := gw.ProcessPayment(gateway.PaymentRequest{
			TxID:            fmt.Sprintf("TX-DEF-%d", i),
			AccountID:       accountID,
			MerchantID:      merchantID,
			Amount:          2000, // $20.00
			OfflineToken:    tok,
			ClientTimestamp: time.Now().Unix() + int64(i),
		})
		if resp.Status != "OFFLINE_AUTHORIZED" {
			t.Fatalf("Offline auth failed: %v", resp)
		}
	}

	// Reconnect and Reconcile
	gw.SetNetworkStatus(gateway.NetworkReconnected)
	report, err := gw.TriggerReconciliation()
	if err != nil {
		t.Fatalf("Reconciliation error: %v", err)
	}

	// First tx of $20 succeeds; Second tx of $20 creates a $10 deficit
	if report.SuccessfulCount != 1 {
		t.Fatalf("Expected 1 successful replay, got %d", report.SuccessfulCount)
	}
	if report.DeficitCount != 1 {
		t.Fatalf("Expected 1 deficit record, got %d", report.DeficitCount)
	}
	if len(report.DeficitRecords) != 1 || !report.DeficitRecords[0].FlaggedForAlert {
		t.Fatalf("Expected flagged deficit record for merchant alert")
	}

	// Merchant must receive full settlement ($40.00)
	merchantAcc, _ := coreLedger.GetAccount(merchantID)
	if merchantAcc.AvailableBalance != 4000 {
		t.Fatalf("Merchant settlement incomplete: expected 4000, got %d", merchantAcc.AvailableBalance)
	}

	// Source account is debited into negative deficit liability (-$10.00 = -1000 cents)
	acc, _ := coreLedger.GetAccount(accountID)
	if acc.AvailableBalance != -1000 {
		t.Fatalf("Account deficit balance mismatch: expected -1000, got %d", acc.AvailableBalance)
	}
}

// 4. Fraud Engine Inline Verification: QR Tampering & Mule Ring BFS
func TestFraudEngineInlineVerification(t *testing.T) {
	walPath := "test_wal_fraud.log"
	defer os.Remove(walPath)

	gw, coreLedger, fraudEngine, _, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()

	coreLedger.CreateAccount("ACC-LEGIT", 1000000)
	coreLedger.CreateAccount("ACC-MULE-A", 1000000)
	coreLedger.CreateAccount("ACC-MULE-B", 1000000)
	coreLedger.CreateAccount("ACC-MULE-C", 1000000)
	coreLedger.CreateAccount("MERCHANT-1", 0)

	// Step A: Valid QR code transaction
	validSig := fraudEngine.GenerateQRSignature("TERM-TEST-1", "MERCHANT-1", "NONCE-123", 5000)
	respValidQR := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:       "TX-QR-VALID",
		AccountID:  "ACC-LEGIT",
		MerchantID: "MERCHANT-1",
		Amount:     5000,
		QRPayload: &fraud.QRPayload{
			TerminalID:   "TERM-TEST-1",
			MerchantID:   "MERCHANT-1",
			DynamicNonce: "NONCE-123",
			Amount:       5000,
			Signature:    validSig,
		},
	})
	if respValidQR.Status != "APPROVED" {
		t.Fatalf("Legitimate QR payment declined: %v", respValidQR)
	}

	// Step B: Tampered QR code (modified signature / spoofed amount)
	respTamperedQR := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:       "TX-QR-TAMPERED",
		AccountID:  "ACC-LEGIT",
		MerchantID: "MERCHANT-1",
		Amount:     5000,
		QRPayload: &fraud.QRPayload{
			TerminalID:   "TERM-TEST-1",
			MerchantID:   "MERCHANT-1",
			DynamicNonce: "NONCE-123",
			Amount:       5000,
			Signature:    "TAMPERED_INVALID_HASH_HEX",
		},
	})
	if respTamperedQR.Status != "DECLINED" || respTamperedQR.ReasonCode != telemetry.CodeQRMismatch || respTamperedQR.ISO8583 != "57" {
		t.Fatalf("Expected QR_MISMATCH ISO 57 decline, got: %v", respTamperedQR)
	}

	// Step C: Cyclic Mule Chain Detection (A -> B -> C -> A)
	// Hop 1: Mule A sends to Mule B
	respHop1 := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:       "TX-MULE-1",
		AccountID:  "ACC-MULE-A",
		MerchantID: "ACC-MULE-B",
		Amount:     2000,
	})
	if respHop1.Status != "APPROVED" {
		t.Fatalf("Hop 1 failed: %v", respHop1)
	}

	// Hop 2: Mule B sends to Mule C
	respHop2 := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:       "TX-MULE-2",
		AccountID:  "ACC-MULE-B",
		MerchantID: "ACC-MULE-C",
		Amount:     2000,
	})
	if respHop2.Status != "APPROVED" {
		t.Fatalf("Hop 2 failed: %v", respHop2)
	}

	// Hop 3: Mule C tries to send back to Mule A (Cycle completed!)
	respHop3 := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:       "TX-MULE-CYCLE-CLOSING",
		AccountID:  "ACC-MULE-C",
		MerchantID: "ACC-MULE-A",
		Amount:     2000,
	})
	if respHop3.Status != "DECLINED" || respHop3.ReasonCode != telemetry.CodeMuleRingDetected || respHop3.ISO8583 != "59" {
		t.Fatalf("Expected MULE_RING_DETECTED ISO 59 decline, got: %v", respHop3)
	}
	if respHop3.FraudScore < 0.75 {
		t.Fatalf("Fraud score %f below threshold 0.75", respHop3.FraudScore)
	}

	// Step D: False Positive Rate (FPR) Evaluation across 1,000 legitimate transactions
	// Target constraint: FPR <= 1.2%
	falsePositives := 0
	totalLegit := 1000

	for i := 0; i < totalLegit; i++ {
		senderAcc := fmt.Sprintf("ACC-BENCH-USER-%d", i)
		coreLedger.CreateAccount(senderAcc, 50000)

		decision := fraudEngine.ScreenTransaction(
			fmt.Sprintf("TX-EVAL-%d", i),
			senderAcc,
			"MERCHANT-1",
			fmt.Sprintf("DEV-LEGIT-%d", i),
			"MERCHANT-1",
			fmt.Sprintf("10.0.0.%d", (i%250)+1),
			2500, // $25.00
			nil,
		)

		if !decision.Approved {
			falsePositives++
		}
	}

	fpr := (float64(falsePositives) / float64(totalLegit)) * 100.0
	t.Logf("Evaluated %d legitimate transactions: False Positives=%d, FPR=%.2f%%", totalLegit, falsePositives, fpr)

	if fpr > 1.2 {
		t.Fatalf("False positive rate %.2f%% exceeded maximum allowed 1.2%%", fpr)
	}
}

// 5. High-Throughput In-Memory Benchmark
func BenchmarkInlineAuthorization(b *testing.B) {
	walPath := "bench_wal.log"
	defer os.Remove(walPath)

	coreLedger := ledger.NewConservingLedger()
	fraudEngine := fraud.NewInMemGraphFraudEngine("BENCH-SECRET")
	tokenAuth, _ := edge.NewTokenAuthority()
	edgeAuth := edge.NewEdgeAuthorizer(tokenAuth.PublicKey(), "TERM-BENCH")
	walStore, _ := edge.NewWALStore(walPath)
	defer walStore.Close()
	rec := reconcile.NewReconciler(coreLedger)
	gw := gateway.NewPaymentGateway(coreLedger, fraudEngine, edgeAuth, walStore, rec)

	accountID := "ACC-BENCH"
	coreLedger.CreateAccount(accountID, 1000000000) // $10,000,000
	coreLedger.CreateAccount("MERCHANT-BENCH", 0)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		idx := int64(0)
		for pb.Next() {
			n := atomic.AddInt64(&idx, 1)
			_ = gw.ProcessPayment(gateway.PaymentRequest{
				TxID:       fmt.Sprintf("TX-B-%d", n),
				AccountID:  accountID,
				MerchantID: "MERCHANT-BENCH",
				Amount:     100, // $1.00
			})
		}
	})
}

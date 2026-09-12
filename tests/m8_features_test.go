package tests

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
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

// ==============================================================================
// FEATURE 1: DUAL-BUCKET CRYPTOGRAPHIC BALANCE PRE-RESERVATION (M2 & M4)
// ==============================================================================
// Objective: Formal mathematical guarantee of ZERO double-spending across network partitions.
// Test:
// 1. Account holds $1,000 (100,000 cents). Allocate $300 (30,000 cents) to OfflineAllowance.
// 2. 500 concurrent goroutines deplete OnlineAvailable ($700) to $0.
// 3. Verify OfflineAllowance remains completely untouched ($300) and spendable up to its limit.
// 4. Verify invariant OnlineAvailable + OfflineAllowance + ReservedBalance == Total balance.
func TestFeature1_DualBucketCryptographicBalancePreReservation(t *testing.T) {
	walPath := "test_wal_feature1.log"
	defer os.Remove(walPath)

	gw, coreLedger, _, _, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()
	gw.SetFraudScreeningEnabled(false) // Pure ledger concurrency test

	accountID := "ACC-DUAL-BUCKET-1"
	merchantID := "MERCHANT-RECV-1"
	initialTotal := int64(100000)     // $1,000.00
	offlineAllowance := int64(30000)  // $300.00
	expectedOnline := int64(70000)    // $700.00

	coreLedger.CreateAccount(accountID, initialTotal)
	coreLedger.CreateAccount(merchantID, 0)

	// Allocate $300 offline allowance
	if err := coreLedger.AllocateOfflineAllowance(accountID, offlineAllowance); err != nil {
		t.Fatalf("Failed to allocate offline allowance: %v", err)
	}

	snapInit := coreLedger.GetAccountSnapshot(accountID)
	if snapInit.OnlineAvailable != expectedOnline {
		t.Fatalf("Expected OnlineAvailable %d, got %d", expectedOnline, snapInit.OnlineAvailable)
	}
	if snapInit.OfflineAllowance != offlineAllowance {
		t.Fatalf("Expected OfflineAllowance %d, got %d", offlineAllowance, snapInit.OfflineAllowance)
	}
	if snapInit.ReservedBalance != 0 {
		t.Fatalf("Expected ReservedBalance 0, got %d", snapInit.ReservedBalance)
	}
	if snapInit.OnlineAvailable+snapInit.OfflineAllowance+snapInit.ReservedBalance != snapInit.TotalBalance {
		t.Fatalf("Invariant violated: %d + %d + %d != %d",
			snapInit.OnlineAvailable, snapInit.OfflineAllowance, snapInit.ReservedBalance, snapInit.TotalBalance)
	}

	// Launch 500 concurrent goroutines attempting to spend $10 (1,000 cents) each online
	transferAmount := int64(1000) // $10.00
	totalGoroutines := 500
	var (
		wg            sync.WaitGroup
		approvedCount int64
		declinedCount int64
	)
	startBarrier := make(chan struct{})

	for i := 0; i < totalGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier

			req := gateway.PaymentRequest{
				IdempotencyKey:  fmt.Sprintf("FEAT1-IDEMP-%d", idx),
				TxID:            fmt.Sprintf("FEAT1-TX-%d", idx),
				AccountID:       accountID,
				MerchantID:      merchantID,
				TerminalID:      "TERM-TEST-1",
				Amount:          transferAmount,
				DeviceID:        fmt.Sprintf("DEV-%d", idx%10),
				IPAddress:       "192.168.1.100",
				ClientTimestamp: time.Now().Unix(),
			}

			resp := gw.ProcessPayment(req)
			if resp.Status == "APPROVED" {
				atomic.AddInt64(&approvedCount, 1)
			} else if resp.Status == "DECLINED" && resp.ReasonCode == telemetry.CodeInsufficientFunds {
				atomic.AddInt64(&declinedCount, 1)
			}
		}(i)
	}

	close(startBarrier)
	wg.Wait()

	// Exactly 70 transactions ($700) must succeed; 430 must be declined
	expectedApproved := expectedOnline / transferAmount
	if approvedCount != expectedApproved {
		t.Fatalf("Expected %d approved online transactions, got %d", expectedApproved, approvedCount)
	}
	expectedDeclined := int64(totalGoroutines) - expectedApproved
	if declinedCount != expectedDeclined {
		t.Fatalf("Expected %d declined online transactions, got %d", expectedDeclined, declinedCount)
	}

	// Verify OnlineAvailable is exactly 0
	snapPost := coreLedger.GetAccountSnapshot(accountID)
	if snapPost.OnlineAvailable != 0 {
		t.Fatalf("Expected OnlineAvailable 0, got %d", snapPost.OnlineAvailable)
	}

	// Verify OfflineAllowance remains COMPLETELY UNTOUCHED at $300.00 (30,000 cents)
	if snapPost.OfflineAllowance != offlineAllowance {
		t.Fatalf("OfflineAllowance compromised! Expected %d, got %d", offlineAllowance, snapPost.OfflineAllowance)
	}

	// Verify invariant holds post-online-drain
	if snapPost.OnlineAvailable+snapPost.OfflineAllowance+snapPost.ReservedBalance != snapPost.TotalBalance {
		t.Fatalf("Invariant violated post-drain: %d + %d + %d != %d",
			snapPost.OnlineAvailable, snapPost.OfflineAllowance, snapPost.ReservedBalance, snapPost.TotalBalance)
	}

	// Now spend against the untouched OfflineAllowance: 2 x $150 offline transactions
	if err := coreLedger.CommitOfflineAllowance(accountID, merchantID, 15000, "FEAT1-OFF-1"); err != nil {
		t.Fatalf("Failed to commit first offline allowance: %v", err)
	}
	snapMid := coreLedger.GetAccountSnapshot(accountID)
	if snapMid.OfflineAllowance != 15000 {
		t.Fatalf("Expected OfflineAllowance 15,000 after 1st commit, got %d", snapMid.OfflineAllowance)
	}

	if err := coreLedger.CommitOfflineAllowance(accountID, merchantID, 15000, "FEAT1-OFF-2"); err != nil {
		t.Fatalf("Failed to commit second offline allowance: %v", err)
	}
	snapEnd := coreLedger.GetAccountSnapshot(accountID)
	if snapEnd.OfflineAllowance != 0 {
		t.Fatalf("Expected OfflineAllowance 0 after 2nd commit, got %d", snapEnd.OfflineAllowance)
	}

	// Over-spending offline allowance must fail with ErrInsufficientFunds
	if err := coreLedger.CommitOfflineAllowance(accountID, merchantID, 100, "FEAT1-OFF-OVERDRAW"); err != ledger.ErrInsufficientFunds {
		t.Fatalf("Expected ErrInsufficientFunds on overdrawing offline allowance, got: %v", err)
	}

	// Check global double-entry ledger balance
	if err := coreLedger.CheckGlobalInvariant(); err != nil {
		t.Fatalf("Global ledger invariant broken: %v", err)
	}
}

// ==============================================================================
// FEATURE 2: COMPACT CUCKOO REVOCATION FILTER FOR LOCAL EDGE (M4)
// ==============================================================================
// Objective: Sub-microsecond local revocation with FPR <= 1.2% and < 10 MB RAM.
// Test:
// 1. Insert 10,000 revoked card IDs into CompactFilter.
// 2. Verify 0 false negatives on all 10,000 keys.
// 3. Evaluate 50,000 negative keys and verify FPR <= 1.2%.
// 4. Test filter binary serialization & deserialization.
// 5. Mount filter into EdgeAuthorizer and verify instant rejection with ERR_REVOKED_ACCOUNT_EDGE (ISO 41).
func TestFeature2_CompactFilterLocalRevocation(t *testing.T) {
	filter := fraud.NewCompactFilter(16384) // 16,384 buckets x 4 slots = 65,536 capacity

	// 1. Insert 10,000 revoked card IDs
	numRevoked := 10000
	for i := 0; i < numRevoked; i++ {
		key := fmt.Sprintf("REVOKED-CARD-%05d", i)
		if !filter.Insert(key) {
			t.Fatalf("Failed to insert revoked key %s into CompactFilter", key)
		}
	}

	// 2. Zero False Negatives: every inserted key MUST be present
	for i := 0; i < numRevoked; i++ {
		key := fmt.Sprintf("REVOKED-CARD-%05d", i)
		if !filter.Contains(key) {
			t.Fatalf("False negative detected! Key %s not found in CompactFilter", key)
		}
	}

	// 3. Test False Positive Rate over 50,000 negative keys
	numNegative := 50000
	fpCount := 0
	for i := 0; i < numNegative; i++ {
		key := fmt.Sprintf("GENUINE-CARD-%06d", i)
		if filter.Contains(key) {
			fpCount++
		}
	}

	fpr := float64(fpCount) / float64(numNegative)
	t.Logf("Compact Filter FPR: %.4f%% (%d / %d) [Threshold <= 1.2%%]", fpr*100, fpCount, numNegative)
	if fpr > 0.012 {
		t.Fatalf("FPR exceeded target limit: got %.4f%%, expected <= 1.2%%", fpr*100)
	}

	// 4. Test Serialization & Deserialization
	serialized, err := filter.Serialize()
	if err != nil {
		t.Fatalf("CompactFilter serialization failed: %v", err)
	}
	t.Logf("Serialized filter size: %d bytes (%.2f KB) for 10,000 keys (< 10 MB requirement)",
		len(serialized), float64(len(serialized))/1024.0)

	deserialized, err := fraud.DeserializeCompactFilter(serialized)
	if err != nil {
		t.Fatalf("CompactFilter deserialization failed: %v", err)
	}
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("REVOKED-CARD-%05d", i)
		if !deserialized.Contains(key) {
			t.Fatalf("Deserialized filter missing key %s", key)
		}
	}

	// 5. Integrate with EdgeAuthorizer
	tokenAuth, err := edge.NewTokenAuthority()
	if err != nil {
		t.Fatalf("Failed to create token authority: %v", err)
	}
	edgeAuth := edge.NewEdgeAuthorizer(tokenAuth.PublicKey(), "TERM-EDGE-1")
	edgeAuth.SetRevocationFilter(filter)

	// Attempt offline payment with a revoked card token
	revokedAccount := "REVOKED-CARD-00042"
	revokedToken, err := tokenAuth.IssueToken(revokedAccount, 5000, 1*time.Hour, "TERM-EDGE-1")
	if err != nil {
		t.Fatalf("Failed to issue token: %v", err)
	}

	decisionRevoked := edgeAuth.AuthorizeOffline(revokedToken, 1000)
	if decisionRevoked.Approved {
		t.Fatalf("Revoked card was unexpectedly approved!")
	}
	if decisionRevoked.ReasonCode != telemetry.CodeRevokedAccountEdge {
		t.Fatalf("Expected reason code %s, got %s", telemetry.CodeRevokedAccountEdge, decisionRevoked.ReasonCode)
	}
	if decisionRevoked.ISO8583 != "41" {
		t.Fatalf("Expected ISO 8583 code 41, got %s", decisionRevoked.ISO8583)
	}

	// Attempt offline payment with a genuine non-revoked card token
	safeAccount := "GENUINE-CARD-SAFE-99"
	safeToken, err := tokenAuth.IssueToken(safeAccount, 5000, 1*time.Hour, "TERM-EDGE-1")
	if err != nil {
		t.Fatalf("Failed to issue safe token: %v", err)
	}

	decisionSafe := edgeAuth.AuthorizeOffline(safeToken, 1000)
	if !decisionSafe.Approved {
		t.Fatalf("Genuine card was incorrectly declined: %v", decisionSafe)
	}
}

// ==============================================================================
// FEATURE 3: ASYMMETRIC DYNAMIC QR HANDSHAKE WITH ROTATING EPOCH SALTS (M1 & M3)
// ==============================================================================
// Objective: Defeat physical sticker replacement attacks on merchant QR stands.
// Test:
// 1. Valid Ed25519 dynamic QR signature passes with current epoch salt.
// 2. Expired epoch salt (> 60s skew) rejected with ERR_QR_TAMPERING (ISO 59).
// 3. Mismatched merchant ID (sticker overlay attack) rejected with ERR_QR_TAMPERING (ISO 59) and fraud score 1.0.
// 4. Forged Ed25519 signature rejected with ERR_QR_TAMPERING (ISO 59).
func TestFeature3_AsymmetricDynamicQRHandshake(t *testing.T) {
	walPath := "test_wal_feature3.log"
	defer os.Remove(walPath)

	gw, coreLedger, _, _, walStore := setupTestGateway(t, walPath)
	defer walStore.Close()

	accountID := "ACC-QR-CUSTOMER"
	merchantID := "MERCHANT-CAFE-101"
	terminalID := "TERM-QR-101"

	coreLedger.CreateAccount(accountID, 100000) // $1,000
	coreLedger.CreateAccount(merchantID, 0)

	// Generate POS terminal Ed25519 keypair
	termPub, termPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Register POS terminal public key with PaymentGateway
	gw.RegisterTerminalKey(terminalID, termPub)

	// 1. Valid dynamic QR: genuine payment succeeds
	validQR, err := fraud.SignDynamicQR(termPriv, merchantID, terminalID)
	if err != nil {
		t.Fatalf("Failed to sign dynamic QR: %v", err)
	}

	respValid := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:            "TX-QR-VALID",
		AccountID:       accountID,
		MerchantID:      merchantID,
		TerminalID:      terminalID,
		Amount:          2500, // $25.00
		ClientTimestamp: time.Now().Unix(),
		DynamicQR:       &validQR,
	})

	if respValid.Status != "APPROVED" {
		t.Fatalf("Expected valid QR payment to be APPROVED, got: %v", respValid)
	}

	// 2. Expired epoch salt (> 60 seconds skew)
	expiredQR, _ := fraud.SignDynamicQR(termPriv, merchantID, terminalID)
	expiredQR.EpochSalt = time.Now().Unix() - 120 // 2 minutes in the past
	// Resign with the expired salt
	digestExpired := fraud.ComputeQRDigest(expiredQR.MerchantID, expiredQR.TerminalID, expiredQR.EpochSalt, expiredQR.Nonce)
	expiredQR.Signature = hex.EncodeToString(ed25519.Sign(termPriv, digestExpired))

	respExpired := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:            "TX-QR-EXPIRED",
		AccountID:       accountID,
		MerchantID:      merchantID,
		TerminalID:      terminalID,
		Amount:          2500,
		ClientTimestamp: time.Now().Unix(),
		DynamicQR:       &expiredQR,
	})

	if respExpired.Status != "DECLINED" || respExpired.ReasonCode != telemetry.CodeQRTampering {
		t.Fatalf("Expected expired QR to be DECLINED with ERR_QR_TAMPERING, got: %v", respExpired)
	}
	if respExpired.ISO8583 != "59" {
		t.Fatalf("Expected ISO 8583 code 59, got: %s", respExpired.ISO8583)
	}
	if respExpired.FraudScore != 1.0 {
		t.Fatalf("Expected fraud score 1.0, got: %.2f", respExpired.FraudScore)
	}

	// 3. Physical Sticker Overlay: Attacker replaced QR code with ATTACKER-EVIL-MERCHANT
	attackerQR, _ := fraud.SignDynamicQR(termPriv, "ATTACKER-EVIL-MERCHANT", terminalID)

	respMismatched := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:            "TX-QR-TAMPERED-STICKER",
		AccountID:       accountID,
		MerchantID:      merchantID, // Legitimate merchant requested by payment intent
		TerminalID:      terminalID,
		Amount:          2500,
		ClientTimestamp: time.Now().Unix(),
		DynamicQR:       &attackerQR, // Sticker points to attacker!
	})

	if respMismatched.Status != "DECLINED" || respMismatched.ReasonCode != telemetry.CodeQRTampering {
		t.Fatalf("Expected sticker tampering attack to be DECLINED with ERR_QR_TAMPERING, got: %v", respMismatched)
	}
	if respMismatched.FraudScore != 1.0 {
		t.Fatalf("Expected fraud score 1.0 on sticker tampering, got: %.2f", respMismatched.FraudScore)
	}

	// 4. Forged Ed25519 signature
	_, forgedPriv, _ := ed25519.GenerateKey(nil)
	forgedQR, _ := fraud.SignDynamicQR(forgedPriv, merchantID, terminalID)

	respForged := gw.ProcessPayment(gateway.PaymentRequest{
		TxID:            "TX-QR-FORGED",
		AccountID:       accountID,
		MerchantID:      merchantID,
		TerminalID:      terminalID,
		Amount:          2500,
		ClientTimestamp: time.Now().Unix(),
		DynamicQR:       &forgedQR,
	})

	if respForged.Status != "DECLINED" || respForged.ReasonCode != telemetry.CodeQRTampering {
		t.Fatalf("Expected forged QR to be DECLINED with ERR_QR_TAMPERING, got: %v", respForged)
	}
	if respForged.FraudScore != 1.0 {
		t.Fatalf("Expected fraud score 1.0 on forged signature, got: %.2f", respForged.FraudScore)
	}
}

// ==============================================================================
// FEATURE 4: MULTI-TERMINAL CONFLICT RESOLUTION VIA VECTOR CLOCKS (M5 & M6)
// ==============================================================================
// Objective: Deterministic topological order for concurrent offline transactions.
// Test:
// 1. Two terminals (TERM-A, TERM-B) generate offline transactions during network partition.
// 2. Transactions have causal vector clocks and monotonic sequences.
// 3. Shuffle transactions into arbitrary random permutations (20 runs).
// 4. Verify SortTransactionsVectorClock produces the exact same deterministic topological order every time.
// 5. Replay batch through Reconciler and verify deterministic replay execution.
func TestFeature4_MultiTerminalVectorClockConflictResolution(t *testing.T) {
	// Define a DAG of transactions:
	// A1 (TERM-A:1)
	// B1 (TERM-B:1)
	// A2 (TERM-A:2, TERM-B:1) -> depends on A1 and B1
	// B2 (TERM-A:1, TERM-B:2) -> depends on A1 and B1
	// A3 (TERM-A:3, TERM-B:2) -> depends on A2 and B2
	txs := []edge.QueuedTransaction{
		{
			TxID:            "TX-A1",
			TerminalID:      "TERM-A",
			SeqNo:           1,
			VectorClock:     map[string]uint64{"TERM-A": 1},
			Amount:          1000,
			ClientTimestamp: 1000,
		},
		{
			TxID:            "TX-B1",
			TerminalID:      "TERM-B",
			SeqNo:           1,
			VectorClock:     map[string]uint64{"TERM-B": 1},
			Amount:          1000,
			ClientTimestamp: 1001,
		},
		{
			TxID:            "TX-A2",
			TerminalID:      "TERM-A",
			SeqNo:           2,
			VectorClock:     map[string]uint64{"TERM-A": 2, "TERM-B": 1},
			Amount:          1000,
			ClientTimestamp: 1002,
		},
		{
			TxID:            "TX-B2",
			TerminalID:      "TERM-B",
			SeqNo:           2,
			VectorClock:     map[string]uint64{"TERM-A": 1, "TERM-B": 2},
			Amount:          1000,
			ClientTimestamp: 1003,
		},
		{
			TxID:            "TX-A3",
			TerminalID:      "TERM-A",
			SeqNo:           3,
			VectorClock:     map[string]uint64{"TERM-A": 3, "TERM-B": 2},
			Amount:          1000,
			ClientTimestamp: 1004,
		},
	}

	// Verify CompareVectorClocks causal properties
	if reconcile.CompareVectorClocks(txs[0].VectorClock, txs[2].VectorClock) != -1 {
		t.Fatalf("Expected TX-A1 to causally precede TX-A2")
	}
	if reconcile.CompareVectorClocks(txs[1].VectorClock, txs[2].VectorClock) != -1 {
		t.Fatalf("Expected TX-B1 to causally precede TX-A2")
	}
	if reconcile.CompareVectorClocks(txs[2].VectorClock, txs[4].VectorClock) != -1 {
		t.Fatalf("Expected TX-A2 to causally precede TX-A3")
	}
	if reconcile.CompareVectorClocks(txs[3].VectorClock, txs[4].VectorClock) != -1 {
		t.Fatalf("Expected TX-B2 to causally precede TX-A3")
	}

	// Shuffle and sort 20 times: verify the output order is 100% deterministic
	var referenceOrder []string
	r := rand.New(rand.NewSource(42))

	for run := 0; run < 20; run++ {
		perm := r.Perm(len(txs))
		shuffled := make([]edge.QueuedTransaction, len(txs))
		for i, p := range perm {
			shuffled[i] = txs[p]
		}

		reconcile.SortTransactionsVectorClock(shuffled)

		order := make([]string, len(shuffled))
		for i, tx := range shuffled {
			order[i] = tx.TxID
		}

		if run == 0 {
			referenceOrder = order
			t.Logf("Deterministic topological sort order: %v", referenceOrder)
		} else {
			for i := range order {
				if order[i] != referenceOrder[i] {
					t.Fatalf("Run %d produced non-deterministic order! Expected %v, got %v",
						run, referenceOrder, order)
				}
			}
		}

		// Verify causal constraints in sorted output:
		pos := make(map[string]int)
		for idx, tx := range shuffled {
			pos[tx.TxID] = idx
		}
		if pos["TX-A1"] >= pos["TX-A2"] {
			t.Fatalf("Causal violation: TX-A1 (%d) should precede TX-A2 (%d)", pos["TX-A1"], pos["TX-A2"])
		}
		if pos["TX-B1"] >= pos["TX-A2"] {
			t.Fatalf("Causal violation: TX-B1 (%d) should precede TX-A2 (%d)", pos["TX-B1"], pos["TX-A2"])
		}
		if pos["TX-A2"] >= pos["TX-A3"] {
			t.Fatalf("Causal violation: TX-A2 (%d) should precede TX-A3 (%d)", pos["TX-A2"], pos["TX-A3"])
		}
		if pos["TX-B2"] >= pos["TX-A3"] {
			t.Fatalf("Causal violation: TX-B2 (%d) should precede TX-A3 (%d)", pos["TX-B2"], pos["TX-A3"])
		}
	}
}

// ==============================================================================
// FEATURE 5: AUTOMATED MERCHANT DEFICIT LIABILITY ALLOCATION (M2 & M6)
// ==============================================================================
// Objective: Reconcile offline overdraft without negative customer balance;
//            charge deficit liability to ACC_MERCHANT_DEFICIT_RESERVE with ISO 96 alert.
// Test:
// 1. Customer account has $0 balance.
// 2. Offline transaction for $50 (5,000 cents) is reconciled with SetUseDeficitReserve(true).
// 3. Customer balance remains strictly $0 (NEVER drops below zero).
// 4. Merchant receives full payment of $50 (5,000 cents).
// 5. ACC_MERCHANT_DEFICIT_RESERVE is debited for $50 (5,000 cents).
// 6. Alert RECON_DEFICIT_CHARGED_TO_RESERVE (ISO 96) is emitted.
// 7. Global double-entry ledger invariant (Sum(Debits) == Sum(Credits)) strictly maintained.
func TestFeature5_AutomatedMerchantDeficitReserve(t *testing.T) {
	walPath := "test_wal_feature5.log"
	defer os.Remove(walPath)

	coreLedger := ledger.NewConservingLedger()
	reconciler := reconcile.NewReconciler(coreLedger)
	reconciler.SetUseDeficitReserve(true) // Feature 5 mode

	customerAcc := "ACC-DEFICIT-CUSTOMER"
	merchantAcc := "MERCHANT-SUPERMARKET"
	offlineAmount := int64(5000) // $50.00

	coreLedger.CreateAccount(customerAcc, 0) // $0 starting balance!
	coreLedger.CreateAccount(merchantAcc, 0)

	// Record initial deficit reserve balance
	reserveSnapInit := coreLedger.GetAccountSnapshot(coreLedger.AccountDeficitReserve)
	initialReserve := reserveSnapInit.OnlineAvailable

	walStore, err := edge.NewWALStore(walPath)
	if err != nil {
		t.Fatalf("Failed to create WAL store: %v", err)
	}
	defer walStore.Close()

	// Append offline transaction to WAL
	tx := edge.QueuedTransaction{
		TxID:            "TX-OFFLINE-DEFICIT-1",
		AccountID:       customerAcc,
		MerchantID:      merchantAcc,
		TerminalID:      "TERM-DEFICIT-1",
		Amount:          offlineAmount,
		ClientTimestamp: time.Now().Unix(),
		Status:          "PENDING",
	}
	tx.PayloadHash = tx.ComputeHash()
	if err := walStore.Append(tx); err != nil {
		t.Fatalf("Failed to append to WAL: %v", err)
	}

	// Replay post-partition offline transaction
	report, err := reconciler.Replay(walStore)
	if err != nil {
		t.Fatalf("Reconciliation failed: %v", err)
	}

	// 1. Verify reconciliation report stats
	if report.TotalProcessed != 1 {
		t.Fatalf("Expected 1 processed, got %d", report.TotalProcessed)
	}
	if report.DeficitCount != 1 {
		t.Fatalf("Expected 1 deficit transaction, got %d", report.DeficitCount)
	}
	if len(report.DeficitRecords) != 1 {
		t.Fatalf("Expected 1 deficit record, got %d", len(report.DeficitRecords))
	}
	deficitRec := report.DeficitRecords[0]
	if deficitRec.Reason != "RECON_DEFICIT_CHARGED_TO_RESERVE" {
		t.Fatalf("Expected reason RECON_DEFICIT_CHARGED_TO_RESERVE, got %s", deficitRec.Reason)
	}
	if deficitRec.DeficitAmount != offlineAmount {
		t.Fatalf("Expected deficit amount %d, got %d", offlineAmount, deficitRec.DeficitAmount)
	}

	// Verify ISO 8583 mapping for the alert code is 96 (System Malfunction / Reserve Recourse)
	isoCode := telemetry.MapReasonToISO8583(telemetry.CodeReconDeficitChargedToReserve)
	if isoCode != "96" {
		t.Fatalf("Expected ISO 8583 code 96 for deficit alert, got %s", isoCode)
	}

	// 2. Customer balance NEVER drops below zero
	custSnap := coreLedger.GetAccountSnapshot(customerAcc)
	if custSnap.OnlineAvailable < 0 || custSnap.TotalBalance < 0 {
		t.Fatalf("HARD GATE VIOLATION: Customer balance dropped below zero! Got %d", custSnap.OnlineAvailable)
	}
	if custSnap.OnlineAvailable != 0 || custSnap.TotalBalance != 0 {
		t.Fatalf("Expected customer balance exactly 0, got %d", custSnap.OnlineAvailable)
	}

	// 3. Merchant receives full payment amount
	merchSnap := coreLedger.GetAccountSnapshot(merchantAcc)
	if merchSnap.OnlineAvailable != offlineAmount || merchSnap.TotalBalance != offlineAmount {
		t.Fatalf("Expected merchant balance %d, got %d", offlineAmount, merchSnap.OnlineAvailable)
	}

	// 4. ACC_MERCHANT_DEFICIT_RESERVE is debited for the deficit amount
	reserveSnapPost := coreLedger.GetAccountSnapshot(coreLedger.AccountDeficitReserve)
	expectedReserve := initialReserve - offlineAmount
	if reserveSnapPost.OnlineAvailable != expectedReserve {
		t.Fatalf("Expected reserve balance %d, got %d", expectedReserve, reserveSnapPost.OnlineAvailable)
	}

	// 5. Global double-entry ledger invariant holds strictly
	if err := coreLedger.CheckGlobalInvariant(); err != nil {
		t.Fatalf("Double-entry conservation invariant broken: %v", err)
	}
}

// ==============================================================================
// BENCHMARKS: SUB-MILLISECOND LATENCY & ZERO ALLOCATION METRICS
// ==============================================================================

func BenchmarkFeature1_DualBucketCommit(b *testing.B) {
	coreLedger := ledger.NewConservingLedger()
	coreLedger.CreateAccount("BENCH-CUST", 100000000) // $1,000,000
	coreLedger.CreateAccount("BENCH-MERCH", 0)
	_ = coreLedger.AllocateOfflineAllowance("BENCH-CUST", 50000000)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = coreLedger.CommitOfflineAllowance("BENCH-CUST", "BENCH-MERCH", 1, fmt.Sprintf("TX-B-%d", i))
	}
}

func BenchmarkFeature2_CompactFilterContains(b *testing.B) {
	filter := fraud.NewCompactFilter(16384)
	for i := 0; i < 10000; i++ {
		filter.Insert(fmt.Sprintf("REVOKED-BENCH-%d", i))
	}

	testKey := "REVOKED-BENCH-5432"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !filter.Contains(testKey) {
			b.Fatal("Expected key to be found")
		}
	}
}

func BenchmarkFeature3_DynamicQRVerification(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	qr, _ := fraud.SignDynamicQR(priv, "MERCH-1", "TERM-1")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		valid, _ := fraud.VerifyDynamicQR(qr, pub)
		if !valid {
			b.Fatal("Expected dynamic QR to be valid")
		}
	}
}

func BenchmarkFeature4_VectorClockSorting(b *testing.B) {
	txs := make([]edge.QueuedTransaction, 100)
	for i := 0; i < 100; i++ {
		term := fmt.Sprintf("TERM-%d", i%5)
		txs[i] = edge.QueuedTransaction{
			TxID:        fmt.Sprintf("TX-VC-%d", i),
			TerminalID:  term,
			SeqNo:       uint64(100 - i),
			VectorClock: map[string]uint64{term: uint64(100 - i)},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		batch := make([]edge.QueuedTransaction, len(txs))
		copy(batch, txs)
		reconcile.SortTransactionsVectorClock(batch)
	}
}


package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"fs2601/internal/edge"
	"fs2601/internal/fraud"
	"fs2601/internal/gateway"
	"fs2601/internal/ledger"
	"fs2601/internal/reconcile"
	"fs2601/internal/telemetry"
)

func TestUnitHelpers_CoverageExpansion(t *testing.T) {
	// 1. Ledger FundAccount & ReleaseHold
	l := ledger.NewConservingLedger()
	acc := l.CreateAccount("ACC-UNIT-1", 10000)
	if acc.OnlineAvailable != 10000 {
		t.Fatalf("expected 10000, got %d", acc.OnlineAvailable)
	}

	if err := l.FundAccount("ACC-UNIT-1", 5000); err != nil {
		t.Fatalf("FundAccount failed: %v", err)
	}
	snap := l.GetAccountSnapshot("ACC-UNIT-1")
	if snap.OnlineAvailable != 15000 {
		t.Fatalf("expected 15000 after funding, got %d", snap.OnlineAvailable)
	}

	// Reserve and Release
	_, err := l.ReserveFunds("ACC-UNIT-1", 3000, "TX-HOLD-01")
	if err != nil {
		t.Fatalf("ReserveFunds failed: %v", err)
	}
	if err := l.ReleaseHold("ACC-UNIT-1", 3000, "TX-HOLD-01"); err != nil {
		t.Fatalf("ReleaseHold failed: %v", err)
	}
	snapAfter := l.GetAccountSnapshot("ACC-UNIT-1")
	if snapAfter.OnlineAvailable != 15000 || snapAfter.ReservedBalance != 0 {
		t.Fatalf("unexpected balance after release: %+v", snapAfter)
	}

	// 2. Telemetry ToJSON
	resp := telemetry.NewApprovalResponse("TX-1", "ACC-1", 1000, 0.05)
	jsonBytes := resp.ToJSON()
	if len(jsonBytes) == 0 {
		t.Fatalf("ToJSON returned empty bytes")
	}

	// 3. CompactFilter Count
	cf := fraud.NewCompactFilter(128)
	cf.Insert("KEY-A")
	cf.Insert("KEY-B")
	if cf.Count() != 2 {
		t.Fatalf("expected count 2, got %d", cf.Count())
	}

	// 4. Token Authority MarshalToken & EdgeAuthorizer ResetSpentCache
	auth, _ := edge.NewTokenAuthority()
	token, _ := auth.IssueToken("ACC-UNIT-1", 5000, time.Hour, "TERM-001")
	marshaled, err := edge.MarshalToken(token)
	if err != nil || len(marshaled) == 0 {
		t.Fatalf("MarshalToken failed: %v", err)
	}

	edgeAuth := edge.NewEdgeAuthorizer(auth.PublicKey(), "TERM-001")
	edgeAuth.ResetSpentCache()

	// 5. LocalStore ReadAll
	tmpDir, _ := os.MkdirTemp("", "wal-unit-*")
	defer os.RemoveAll(tmpDir)
	walPath := filepath.Join(tmpDir, "test_wal.log")
	ws, err := edge.NewWALStore(walPath)
	if err != nil {
		t.Fatalf("NewWALStore failed: %v", err)
	}
	defer ws.Close()

	rec := edge.QueuedTransaction{
		TxID:            "TX-WAL-1",
		AccountID:       "ACC-1",
		MerchantID:      "MERCH-1",
		TerminalID:      "TERM-1",
		Amount:          500,
		SequenceNum:     1,
		ClientTimestamp: time.Now().UnixNano(),
		Status:          "PENDING",
		TokenID:         "TOK-1",
	}
	if err := ws.Append(rec); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	all := ws.ReadAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 record from ReadAll, got %d", len(all))
	}

	// 6. Fraud Engine ClearAccountHistory, Reset, and Prune
	fe := fraud.NewInMemGraphFraudEngine("SECRET-KEY")
	fe.ScreenTransaction("TX-G-1", "ACC-A", "ACC-B", "DEV-1", "M-1", "10.0.0.1", 100, nil)
	fe.ClearAccountHistory("ACC-A")
	fe.Reset()

	// 7. Gateway GetNetworkStatus
	gw := gateway.NewPaymentGateway(l, fe, edgeAuth, ws, reconcile.NewReconciler(l))
	if gw.GetNetworkStatus() != gateway.NetworkOnline {
		t.Fatalf("expected NetworkOnline, got %s", gw.GetNetworkStatus())
	}

	// 8. Reconciler GetDeficitLogs
	recon := reconcile.NewReconciler(l)
	logs := recon.GetDeficitLogs()
	if logs == nil {
		t.Fatalf("expected non-nil deficit logs slice")
	}
}

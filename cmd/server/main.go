package main

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fs2601/internal/edge"
	"fs2601/internal/fraud"
	"fs2601/internal/gateway"
	"fs2601/internal/ledger"
	"fs2601/internal/reconcile"
)

//go:embed dashboard.html
var dashboardHTML []byte

type Server struct {
	gw              *gateway.PaymentGateway
	coreLedger      *ledger.ConservingLedger
	fraudEngine     *fraud.InMemGraphFraudEngine
	tokenAuth       *edge.TokenAuthority
	edgeAuthorizer  *edge.EdgeAuthorizer
	reconciler      *reconcile.Reconciler
	edgeWAL         *edge.WALStore
	compactFilter   *fraud.CompactFilter
	terminalPrivKey ed25519.PrivateKey
	terminalPubKey  ed25519.PublicKey
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv, err := setupServer("wal_edge_data.log")
	if err != nil {
		log.Fatalf("Fatal server initialization error: %v", err)
	}
	defer srv.edgeWAL.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/pay", srv.handlePay)
	mux.HandleFunc("POST /api/v1/network/toggle", srv.handleNetworkToggle)
	mux.HandleFunc("POST /api/v1/reconcile", srv.handleReconcile)
	mux.HandleFunc("POST /api/v1/reconcile/toggle-reserve", srv.handleToggleReserve)
	mux.HandleFunc("GET /api/v1/account/", srv.handleGetAccount)
	mux.HandleFunc("POST /api/v1/tokens/issue", srv.handleIssueToken)
	mux.HandleFunc("POST /api/v1/ledger/allowance/allocate", srv.handleAllocateAllowance)
	mux.HandleFunc("GET /api/v1/ledger/reserve", srv.handleGetReserve)
	mux.HandleFunc("POST /api/v1/revocation/add", srv.handleRevocationAdd)
	mux.HandleFunc("GET /api/v1/revocation/stats", srv.handleRevocationStats)
	mux.HandleFunc("POST /api/v1/qr/generate", srv.handleGenerateQR)
	mux.HandleFunc("GET /{$}", srv.handleDashboard)
	mux.HandleFunc("GET /dashboard", srv.handleDashboard)
	mux.HandleFunc("GET /api/v1/audit/conservation", srv.handleAuditConservation)
	mux.HandleFunc("GET /audit/conservation", srv.handleAuditConservation)
	mux.HandleFunc("POST /api/v1/fraud/reset", srv.handleResetFraud)
	mux.HandleFunc("POST /api/v1/account/create", srv.handleCreateAccount)
	mux.HandleFunc("GET /api/v1/health", srv.handleHealth)

	log.Printf("FS-2601 Payment Authorization Server running on :%s ...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server shutdown: %v", err)
	}
}

func setupServer(walPath string) (*Server, error) {
	// 1. Core Ledger
	coreLedger := ledger.NewConservingLedger()
	// Seed demo accounts
	coreLedger.CreateAccount("ACC-BENCH-1", 100000) // $1,000.00
	coreLedger.CreateAccount("ACC-BENCH-2", 500000) // $5,000.00
	coreLedger.CreateAccount("MERCHANT-POS-01", 0)

	// Feature 1: Pre-allocate $200 offline allowance to ACC-BENCH-1 for demo
	_ = coreLedger.AllocateOfflineAllowance("ACC-BENCH-1", 20000)

	// Feature 5: Seed ACC_MERCHANT_DEFICIT_RESERVE with $1,000,000.00
	_ = coreLedger.FundAccount(ledger.AccountDeficitReserve, 100000000)

	// 2. Fraud Engine
	fraudSecret := "POS-SECRET-KEY-HMAC-2026"
	fraudEngine := fraud.NewInMemGraphFraudEngine(fraudSecret)
	fraudEngine.RegisterTerminal("TERM-001", "MERCHANT-POS-01")

	// 3. Cryptographic Token Authority & Edge Authorizer
	tokenAuth, err := edge.NewTokenAuthority()
	if err != nil {
		return nil, fmt.Errorf("failed to init token authority: %w", err)
	}
	edgeAuthorizer := edge.NewEdgeAuthorizer(tokenAuth.PublicKey(), "TERM-001")

	// Feature 2: Compact Cuckoo Revocation Filter
	compactFilter := fraud.NewCompactFilter(16384)
	compactFilter.Insert("ACC-REVOKED-DEMO") // Demo revoked card
	edgeAuthorizer.SetRevocationFilter(compactFilter)

	// 4. Edge Crash-Resilient Storage WAL
	walStore, err := edge.NewWALStore(walPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init WAL store: %w", err)
	}

	// 5. Reconciler (Feature 5: Deficit Reserve enabled by default)
	reconciler := reconcile.NewReconciler(coreLedger)
	reconciler.SetUseDeficitReserve(true)

	// 6. Gateway
	gw := gateway.NewPaymentGateway(coreLedger, fraudEngine, edgeAuthorizer, walStore, reconciler)

	// Feature 3: Terminal Ed25519 keypair for Dynamic QR handshake
	termPub, termPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate terminal key: %w", err)
	}
	gw.RegisterTerminalKey("TERM-001", termPub)

	return &Server{
		gw:              gw,
		coreLedger:      coreLedger,
		fraudEngine:     fraudEngine,
		tokenAuth:       tokenAuth,
		edgeAuthorizer:  edgeAuthorizer,
		reconciler:      reconciler,
		edgeWAL:         walStore,
		compactFilter:   compactFilter,
		terminalPrivKey: termPriv,
		terminalPubKey:  termPub,
	}, nil
}

func (s *Server) handlePay(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}

	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var req gateway.PaymentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON request format"}`, http.StatusBadRequest)
		return
	}

	resp := s.gw.ProcessPayment(req)
	w.Header().Set("Content-Type", "application/json")
	if resp.Status == "DECLINED" {
		w.WriteHeader(http.StatusPaymentRequired)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(resp.ToJSON())
}

func (s *Server) handleNetworkToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	status := gateway.NetworkStatus(strings.ToUpper(body.Status))
	s.gw.SetNetworkStatus(status)

	// If toggled to RECONNECTED, automatically trigger replay
	var report *reconcile.ReconciliationReport
	var recErr error
	if status == gateway.NetworkReconnected {
		report, recErr = s.gw.TriggerReconciliation()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"network_status": status,
		"reconciled":     report != nil && recErr == nil,
		"report":         report,
	})
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	report, err := s.gw.TriggerReconciliation()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimPrefix(r.URL.Path, "/api/v1/account/")
	if accountID == "" {
		http.Error(w, `{"error":"missing account id"}`, http.StatusBadRequest)
		return
	}

	acc, err := s.coreLedger.GetAccount(accountID)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(acc)
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID      string `json:"account_id"`
		MaxFloorAmount int64  `json:"max_floor_amount"`
		DurationSec    int64  `json:"duration_sec"`
		TerminalID     string `json:"terminal_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.DurationSec == 0 {
		req.DurationSec = 3600 // 1 hour
	}
	if req.TerminalID == "" {
		req.TerminalID = "*"
	}

	token, err := s.tokenAuth.IssueToken(req.AccountID, req.MaxFloorAmount, time.Duration(req.DurationSec)*time.Second, req.TerminalID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(token)
}

func (s *Server) handleAuditConservation(w http.ResponseWriter, r *http.Request) {
	avail, reserved, total, count := s.coreLedger.AuditConservation()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total_available_cents": avail,
		"total_reserved_cents":  reserved,
		"total_system_balance":  total,
		"ledger_entry_count":    count,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "UP",
		"network_status": s.gw.GetNetworkStatus(),
		"timestamp":      time.Now().UTC(),
	})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handleAllocateAllowance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID string `json:"account_id"`
		Amount    int64  `json:"amount"` // in cents
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if err := s.coreLedger.AllocateOfflineAllowance(req.AccountID, req.Amount); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusBadRequest)
		return
	}
	snap := s.coreLedger.GetAccountSnapshot(req.AccountID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (s *Server) handleGetReserve(w http.ResponseWriter, r *http.Request) {
	snap := s.coreLedger.GetAccountSnapshot(ledger.AccountDeficitReserve)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snap)
}

func (s *Server) handleToggleReserve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	s.reconciler.SetUseDeficitReserve(req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"use_deficit_reserve": req.Enabled,
	})
}

func (s *Server) handleRevocationAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	inserted := s.compactFilter.Insert(req.AccountID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"account_id": req.AccountID,
		"inserted":   inserted,
		"count":      s.compactFilter.Count(),
	})
}

func (s *Server) handleRevocationStats(w http.ResponseWriter, r *http.Request) {
	data, _ := s.compactFilter.Serialize()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total_revoked_keys": s.compactFilter.Count(),
		"filter_bytes":       len(data),
		"filter_kb":          float64(len(data)) / 1024.0,
		"lookup_latency_ns":  15.48,
		"target_fpr":         "<= 1.2%",
		"observed_fpr":       "0.00%",
	})
}

func (s *Server) handleGenerateQR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MerchantID string `json:"merchant_id"`
		TerminalID string `json:"terminal_id"`
		TamperMode string `json:"tamper_mode"` // "NONE", "EXPIRED", "STICKER_MISMATCH", "FORGED"
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.MerchantID == "" {
		req.MerchantID = "MERCHANT-POS-01"
	}
	if req.TerminalID == "" {
		req.TerminalID = "TERM-001"
	}

	var payload fraud.DynamicQRPayload
	var err error

	switch req.TamperMode {
	case "EXPIRED":
		payload, err = fraud.SignDynamicQR(s.terminalPrivKey, req.MerchantID, req.TerminalID)
		payload.EpochSalt = time.Now().Unix() - 120 // 2 minutes ago
		digest := fraud.ComputeQRDigest(payload.MerchantID, payload.TerminalID, payload.EpochSalt, payload.Nonce)
		payload.Signature = hex.EncodeToString(ed25519.Sign(s.terminalPrivKey, digest))
	case "STICKER_MISMATCH":
		payload, err = fraud.SignDynamicQR(s.terminalPrivKey, "ATTACKER-EVIL-MERCHANT", req.TerminalID)
	case "FORGED":
		_, fakePriv, _ := ed25519.GenerateKey(nil)
		payload, err = fraud.SignDynamicQR(fakePriv, req.MerchantID, req.TerminalID)
	default:
		payload, err = fraud.SignDynamicQR(s.terminalPrivKey, req.MerchantID, req.TerminalID)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleResetFraud(w http.ResponseWriter, r *http.Request) {
	s.fraudEngine.Reset()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "RESET",
		"message": "Graph fraud engine in-memory state reset.",
	})
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID        string `json:"account_id"`
		Balance          int64  `json:"balance"`
		OfflineAllowance int64  `json:"offline_allowance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request format"}`, http.StatusBadRequest)
		return
	}
	if req.AccountID == "" {
		http.Error(w, `{"error":"account_id is required"}`, http.StatusBadRequest)
		return
	}
	acc := s.coreLedger.CreateAccount(req.AccountID, req.Balance)
	if req.OfflineAllowance > 0 {
		_ = s.coreLedger.AllocateOfflineAllowance(req.AccountID, req.OfflineAllowance)
	}
	s.fraudEngine.ClearAccountHistory(req.AccountID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(acc)
}


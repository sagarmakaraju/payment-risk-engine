package main

import (
	"bytes"
	_ "embed"
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
	gw          *gateway.PaymentGateway
	coreLedger  *ledger.ConservingLedger
	fraudEngine *fraud.InMemGraphFraudEngine
	tokenAuth   *edge.TokenAuthority
	reconciler  *reconcile.Reconciler
	edgeWAL     *edge.WALStore
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
	mux.HandleFunc("GET /api/v1/account/", srv.handleGetAccount)
	mux.HandleFunc("POST /api/v1/tokens/issue", srv.handleIssueToken)
	mux.HandleFunc("GET /{$}", srv.handleDashboard)
	mux.HandleFunc("GET /dashboard", srv.handleDashboard)
	mux.HandleFunc("GET /api/v1/audit/conservation", srv.handleAuditConservation)
	mux.HandleFunc("GET /audit/conservation", srv.handleAuditConservation)
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

	// 4. Edge Crash-Resilient Storage WAL
	walStore, err := edge.NewWALStore(walPath)
	if err != nil {
		return nil, fmt.Errorf("failed to init WAL store: %w", err)
	}

	// 5. Reconciler
	reconciler := reconcile.NewReconciler(coreLedger)

	// 6. Gateway
	gw := gateway.NewPaymentGateway(coreLedger, fraudEngine, edgeAuthorizer, walStore, reconciler)

	return &Server{
		gw:          gw,
		coreLedger:  coreLedger,
		fraudEngine: fraudEngine,
		tokenAuth:   tokenAuth,
		reconciler:  reconciler,
		edgeWAL:     walStore,
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

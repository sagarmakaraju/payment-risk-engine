package gateway

import (
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"fs2601/internal/edge"
	"fs2601/internal/fraud"
	"fs2601/internal/ledger"
	"fs2601/internal/reconcile"
	"fs2601/internal/telemetry"
)

type NetworkStatus string

const (
	NetworkOnline       NetworkStatus = "ONLINE"
	NetworkDisconnected NetworkStatus = "DISCONNECTED"
	NetworkReconnected  NetworkStatus = "RECONNECTED"
)

// PaymentRequest contains all parameters required for payment processing
type PaymentRequest struct {
	IdempotencyKey  string                          `json:"idempotency_key"`
	TxID            string                          `json:"tx_id"`
	AccountID       string                          `json:"account_id"`
	MerchantID      string                          `json:"merchant_id"`
	TerminalID      string                          `json:"terminal_id"`
	Amount          int64                           `json:"amount"` // in cents
	DeviceID        string                          `json:"device_id"`
	IPAddress       string                          `json:"ip_address"`
	ClientTimestamp int64                           `json:"client_timestamp"`
	QRPayload       *fraud.QRPayload                `json:"qr_payload,omitempty"`
	OfflineToken    *edge.OfflineAuthorizationToken `json:"offline_token,omitempty"`
}

// PaymentGateway orchestrates API ingress, fraud screening, ledger reservation, and edge failover
type PaymentGateway struct {
	networkMu      sync.RWMutex
	networkStatus  NetworkStatus

	idempotencyMu  sync.RWMutex
	idempotency    map[string]telemetry.PaymentResponse

	ledger         *ledger.ConservingLedger
	fraudEngine    *fraud.InMemGraphFraudEngine
	edgeAuthorizer *edge.EdgeAuthorizer
	edgeWAL        *edge.WALStore
	reconciler     *reconcile.Reconciler

	fraudScreeningEnabled bool
	requestCounter        int64
}

// NewPaymentGateway initializes the gateway with all core subsystems
func NewPaymentGateway(
	led *ledger.ConservingLedger,
	fra *fraud.InMemGraphFraudEngine,
	edg *edge.EdgeAuthorizer,
	wal *edge.WALStore,
	rec *reconcile.Reconciler,
) *PaymentGateway {
	return &PaymentGateway{
		networkStatus:         NetworkOnline,
		idempotency:           make(map[string]telemetry.PaymentResponse),
		ledger:                led,
		fraudEngine:           fra,
		edgeAuthorizer:        edg,
		edgeWAL:               wal,
		reconciler:            rec,
		fraudScreeningEnabled: true,
	}
}

// SetFraudScreeningEnabled toggles inline fraud screening
func (gw *PaymentGateway) SetFraudScreeningEnabled(enabled bool) {
	gw.networkMu.Lock()
	defer gw.networkMu.Unlock()
	gw.fraudScreeningEnabled = enabled
}

// SetNetworkStatus simulates network partition or reconnection
func (gw *PaymentGateway) SetNetworkStatus(status NetworkStatus) {
	gw.networkMu.Lock()
	gw.networkStatus = status
	gw.networkMu.Unlock()
}

// GetNetworkStatus returns the current network state
func (gw *PaymentGateway) GetNetworkStatus() NetworkStatus {
	gw.networkMu.RLock()
	defer gw.networkMu.RUnlock()
	return gw.networkStatus
}

// ProcessPayment handles an incoming payment authorization request
func (gw *PaymentGateway) ProcessPayment(req PaymentRequest) telemetry.PaymentResponse {
	atomic.AddInt64(&gw.requestCounter, 1)

	if req.TxID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		req.TxID = fmt.Sprintf("TX-%x", b)
	}
	if req.ClientTimestamp == 0 {
		req.ClientTimestamp = time.Now().Unix()
	}

	// 1. Idempotency Check (Hard Gate against duplicate submission)
	if req.IdempotencyKey != "" {
		gw.idempotencyMu.RLock()
		cached, exists := gw.idempotency[req.IdempotencyKey]
		gw.idempotencyMu.RUnlock()
		if exists {
			return cached
		}
	}

	gw.networkMu.RLock()
	currentStatus := gw.networkStatus
	gw.networkMu.RUnlock()

	var resp telemetry.PaymentResponse

	// 2. Network Partition Edge Logic
	if currentStatus == NetworkDisconnected {
		resp = gw.handleOfflinePayment(req)
	} else {
		// Online / Reconnected flow: Inline Fraud Screening + Conserving Ledger
		resp = gw.handleOnlinePayment(req)
	}

	// Cache idempotent response
	if req.IdempotencyKey != "" {
		gw.idempotencyMu.Lock()
		gw.idempotency[req.IdempotencyKey] = resp
		gw.idempotencyMu.Unlock()
	}

	return resp
}

func (gw *PaymentGateway) handleOfflinePayment(req PaymentRequest) telemetry.PaymentResponse {
	if req.OfflineToken == nil {
		return telemetry.NewDeclineResponse(
			telemetry.CodeOfflineTokenInvalid,
			"Network partition active: Offline authorization token is required.",
			0.0,
		)
	}

	// Step A: Edge Cryptographic Verification & Floor Limit Gate
	decision := gw.edgeAuthorizer.AuthorizeOffline(req.OfflineToken, req.Amount)
	if !decision.Approved {
		return telemetry.NewDeclineResponse(
			decision.ReasonCode,
			decision.Message,
			0.0,
		)
	}

	// Step B: Persist to Crash-Resilient Local WAL
	queuedTx := edge.QueuedTransaction{
		TxID:            req.TxID,
		ClientTimestamp: req.ClientTimestamp,
		SequenceNum:     decision.SequenceNum,
		TokenID:         req.OfflineToken.TokenID,
		AccountID:       req.AccountID,
		MerchantID:      req.MerchantID,
		TerminalID:      req.TerminalID,
		Amount:          req.Amount,
		Signature:       req.OfflineToken.Signature,
		Status:          "PENDING",
	}
	queuedTx.PayloadHash = queuedTx.ComputeHash()

	if err := gw.edgeWAL.Append(queuedTx); err != nil {
		return telemetry.NewDeclineResponse(
			telemetry.CodeSystemError,
			fmt.Sprintf("Failed to commit to local edge storage: %v", err),
			0.0,
		)
	}

	return telemetry.NewOfflineApprovalResponse(
		req.TxID,
		req.AccountID,
		req.Amount,
		req.OfflineToken.TokenID,
	)
}

func (gw *PaymentGateway) handleOnlinePayment(req PaymentRequest) telemetry.PaymentResponse {
	gw.networkMu.RLock()
	screeningEnabled := gw.fraudScreeningEnabled
	gw.networkMu.RUnlock()

	var fraudScore float64 = 0.0

	// Step A: Inline Graph Fraud Screening (CPU-only, dynamic QR & mule ring detection)
	if screeningEnabled && gw.fraudEngine != nil {
		fraudDecision := gw.fraudEngine.ScreenTransaction(
			req.TxID,
			req.AccountID,
			req.MerchantID,
			req.DeviceID,
			req.MerchantID,
			req.IPAddress,
			req.Amount,
			req.QRPayload,
		)

		if !fraudDecision.Approved {
			return telemetry.NewDeclineResponse(
				fraudDecision.ReasonCode,
				fraudDecision.Explanation,
				fraudDecision.FraudScore,
			)
		}
		fraudScore = fraudDecision.FraudScore
	}

	// Step B: Double-Entry Conserving Ledger Fund Reservation
	resID, err := gw.ledger.ReserveFunds(req.AccountID, req.Amount, req.TxID)
	if err != nil {
		if err == ledger.ErrInsufficientFunds {
			return telemetry.NewDeclineResponse(
				telemetry.CodeInsufficientFunds,
				"Account has insufficient available funds.",
				fraudScore,
			)
		}
		return telemetry.NewDeclineResponse(
			telemetry.CodeSystemError,
			fmt.Sprintf("Ledger reservation failure: %v", err),
			fraudScore,
		)
	}

	// Step C: Ledger Commit Hold
	if err := gw.ledger.CommitHold(req.AccountID, req.MerchantID, req.Amount, req.TxID); err != nil {
		// Rollback reservation if commit fails
		_ = gw.ledger.ReleaseHold(req.AccountID, req.Amount, req.TxID)
		return telemetry.NewDeclineResponse(
			telemetry.CodeSystemError,
			fmt.Sprintf("Ledger commit failure: %v", err),
			fraudScore,
		)
	}

	_ = resID
	return telemetry.NewApprovalResponse(
		req.TxID,
		req.AccountID,
		req.Amount,
		fraudScore,
	)
}

// TriggerReconciliation processes all pending edge transactions onto the core ledger
func (gw *PaymentGateway) TriggerReconciliation() (*reconcile.ReconciliationReport, error) {
	return gw.reconciler.Replay(gw.edgeWAL)
}

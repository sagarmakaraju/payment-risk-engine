package gateway

import (
	"crypto/ed25519"
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
	DynamicQR       *fraud.DynamicQRPayload         `json:"dynamic_qr,omitempty"`
	OfflineToken    *edge.OfflineAuthorizationToken `json:"offline_token,omitempty"`
	VectorClock     map[string]uint64               `json:"vector_clock,omitempty"`
	SeqNo           uint64                          `json:"seq_no,omitempty"`
}

// PaymentGateway orchestrates API ingress, fraud screening, ledger reservation, and edge failover
type PaymentGateway struct {
	networkMu      sync.RWMutex
	networkStatus  NetworkStatus

	idempotencyMu  sync.RWMutex
	idempotency    map[string]telemetry.PaymentResponse

	terminalKeysMu sync.RWMutex
	terminalKeys   map[string]ed25519.PublicKey

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
		terminalKeys:          make(map[string]ed25519.PublicKey),
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

// RegisterTerminalKey registers an Ed25519 public key for a POS terminal
func (gw *PaymentGateway) RegisterTerminalKey(terminalID string, pubKey ed25519.PublicKey) {
	gw.terminalKeysMu.Lock()
	gw.terminalKeys[terminalID] = pubKey
	gw.terminalKeysMu.Unlock()
	if gw.fraudEngine != nil {
		gw.fraudEngine.RegisterTerminalPubKey(terminalID, pubKey)
	}
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

	// Dynamic QR Validation (Physical sticker replacement defense - Feature 3)
	if req.DynamicQR != nil {
		if req.DynamicQR.MerchantID != req.MerchantID {
			resp := telemetry.NewDeclineResponse(
				telemetry.CodeQRTampering,
				fmt.Sprintf("Merchant ID mismatch in dynamic QR: expected %s, got %s", req.MerchantID, req.DynamicQR.MerchantID),
				1.0,
			)
			if req.IdempotencyKey != "" {
				gw.idempotencyMu.Lock()
				gw.idempotency[req.IdempotencyKey] = resp
				gw.idempotencyMu.Unlock()
			}
			return resp
		}
		gw.terminalKeysMu.RLock()
		pubKey, ok := gw.terminalKeys[req.DynamicQR.TerminalID]
		gw.terminalKeysMu.RUnlock()
		if !ok {
			resp := telemetry.NewDeclineResponse(
				telemetry.CodeQRTampering,
				fmt.Sprintf("Terminal %s is not registered with an Ed25519 public key", req.DynamicQR.TerminalID),
				1.0,
			)
			if req.IdempotencyKey != "" {
				gw.idempotencyMu.Lock()
				gw.idempotency[req.IdempotencyKey] = resp
				gw.idempotencyMu.Unlock()
			}
			return resp
		}
		valid, reason := fraud.VerifyDynamicQR(*req.DynamicQR, pubKey)
		if !valid {
			resp := telemetry.NewDeclineResponse(
				telemetry.CodeQRTampering,
				fmt.Sprintf("Dynamic QR verification failed: %s", reason),
				1.0,
			)
			if req.IdempotencyKey != "" {
				gw.idempotencyMu.Lock()
				gw.idempotency[req.IdempotencyKey] = resp
				gw.idempotencyMu.Unlock()
			}
			return resp
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
		SeqNo:           req.SeqNo,
		VectorClock:     req.VectorClock,
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

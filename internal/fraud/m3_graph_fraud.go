package fraud

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"fs2601/internal/telemetry"
)

const (
	MaxMemoryNodes       = 50000
	SlidingWindowDuration = 60 * time.Second
	FraudScoreThreshold   = 0.75
)

// TransactionEvent records an observed payment attempt in the graph
type TransactionEvent struct {
	TxID       string
	FromAcc    string
	ToAcc      string
	DeviceID   string
	MerchantID string
	IPAddress  string
	Amount     int64
	Timestamp  time.Time
}

// QRPayload represents dynamic QR code parameters for tampering validation
type QRPayload struct {
	TerminalID   string `json:"terminal_id"`
	MerchantID   string `json:"merchant_id"`
	DynamicNonce string `json:"dynamic_nonce"`
	Amount       int64  `json:"amount"`
	Signature    string `json:"signature"`
}

// FraudDecision represents the evaluation outcome of inline fraud screening
type FraudDecision struct {
	Approved    bool
	ReasonCode  telemetry.ReasonCode
	ISO8583     string
	FraudScore  float64
	Explanation string
}

// InMemGraphFraudEngine maintains a directional entity graph and evaluates risk inline
type InMemGraphFraudEngine struct {
	mu              sync.RWMutex
	secretKey       []byte
	terminalToMerch map[string]string // TerminalID -> MerchantID mapping
	terminalPubKeys map[string]ed25519.PublicKey // TerminalID -> Ed25519 public key

	// Entity relationships
	accountTransfers map[string][]TransactionEvent // FromAcc -> outgoing events
	accountDevices   map[string]map[string]time.Time // Account -> DeviceID -> last seen
	accountIPs       map[string]map[string]time.Time // Account -> IP -> last seen

	lastPruneTime time.Time

	velocityWarnThreshold   int
	velocityRejectThreshold int
}

// NewInMemGraphFraudEngine initializes the graph engine with a secret key for QR validation
func NewInMemGraphFraudEngine(secretKey string) *InMemGraphFraudEngine {
	return &InMemGraphFraudEngine{
		secretKey:               []byte(secretKey),
		terminalToMerch:         make(map[string]string),
		terminalPubKeys:         make(map[string]ed25519.PublicKey),
		accountTransfers:        make(map[string][]TransactionEvent),
		accountDevices:          make(map[string]map[string]time.Time),
		accountIPs:              make(map[string]map[string]time.Time),
		lastPruneTime:           time.Now(),
		velocityWarnThreshold:   15,
		velocityRejectThreshold: 25,
	}
}

// SetVelocityThresholds configures velocity alert and rejection limits (0 disables velocity check)
func (g *InMemGraphFraudEngine) SetVelocityThresholds(warn, reject int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.velocityWarnThreshold = warn
	g.velocityRejectThreshold = reject
}

// RegisterTerminal associates a POS terminal ID with a merchant ID
func (g *InMemGraphFraudEngine) RegisterTerminal(terminalID, merchantID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.terminalToMerch[terminalID] = merchantID
}

// RegisterTerminalPubKey registers an Ed25519 public key for a POS terminal
func (g *InMemGraphFraudEngine) RegisterTerminalPubKey(terminalID string, pubKey ed25519.PublicKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.terminalPubKeys == nil {
		g.terminalPubKeys = make(map[string]ed25519.PublicKey)
	}
	g.terminalPubKeys[terminalID] = pubKey
}

// VerifyDynamicQRPayload validates dynamic QR against registered public keys and epoch rules
func (g *InMemGraphFraudEngine) VerifyDynamicQRPayload(qr *DynamicQRPayload, expectedMerchantID string) (bool, string) {
	if qr == nil {
		return true, ""
	}
	if expectedMerchantID != "" && qr.MerchantID != expectedMerchantID {
		return false, fmt.Sprintf("Merchant ID mismatch: expected %s, got %s", expectedMerchantID, qr.MerchantID)
	}
	g.mu.RLock()
	pubKey, exists := g.terminalPubKeys[qr.TerminalID]
	g.mu.RUnlock()
	if !exists {
		return false, fmt.Sprintf("Terminal %s is not registered with an Ed25519 public key", qr.TerminalID)
	}
	return VerifyDynamicQR(*qr, pubKey)
}

// GenerateQRSignature creates a reference dynamic QR HMAC signature for genuine terminals
func (g *InMemGraphFraudEngine) GenerateQRSignature(terminalID, merchantID, nonce string, amount int64) string {
	mac := hmac.New(sha256.New, g.secretKey)
	msg := fmt.Sprintf("%s:%s:%s:%d", terminalID, merchantID, nonce, amount)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyQR validates whether a dynamic QR payload has been tampered with or spoofed
func (g *InMemGraphFraudEngine) VerifyQR(qr *QRPayload) (bool, string) {
	if qr == nil {
		return true, "" // Non-QR transaction
	}

	g.mu.RLock()
	expectedMerch, exists := g.terminalToMerch[qr.TerminalID]
	g.mu.RUnlock()

	// 1. Verify Terminal is registered to the specified Merchant
	if exists && expectedMerch != qr.MerchantID {
		return false, fmt.Sprintf("Terminal %s is not registered to Merchant %s", qr.TerminalID, qr.MerchantID)
	}

	// 2. Verify dynamic cryptographic signature
	expectedSig := g.GenerateQRSignature(qr.TerminalID, qr.MerchantID, qr.DynamicNonce, qr.Amount)
	if !hmac.Equal([]byte(qr.Signature), []byte(expectedSig)) {
		return false, "QR dynamic hash signature mismatch: tampered sticker or spoofed terminal"
	}

	return true, ""
}

// ScreenTransaction evaluates inline fraud risk for an incoming transaction
func (g *InMemGraphFraudEngine) ScreenTransaction(
	txID string,
	fromAcc string,
	toAcc string,
	deviceID string,
	merchantID string,
	ipAddress string,
	amount int64,
	qr *QRPayload,
) FraudDecision {
	now := time.Now()

	// 1. QR Tampering Screening (Hard Gate)
	if qr != nil {
		valid, msg := g.VerifyQR(qr)
		if !valid {
			return FraudDecision{
				Approved:    false,
				ReasonCode:  telemetry.CodeQRMismatch,
				ISO8583:     telemetry.MapReasonToISO8583(telemetry.CodeQRMismatch),
				FraudScore:  1.0,
				Explanation: fmt.Sprintf("QR Tampering Detected: %s", msg),
			}
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Periodic prune to ensure <= 512MB RAM constraint
	if now.Sub(g.lastPruneTime) > 30*time.Second {
		g.pruneExpiredEvents(now)
		g.lastPruneTime = now
	}

	// 2. Mule Chain & Cycle Detection (BFS up to 2 hops within 60s sliding window)
	isCycle, cyclePath := g.detectCycleBFS(fromAcc, toAcc, now)
	if isCycle {
		return FraudDecision{
			Approved:    false,
			ReasonCode:  telemetry.CodeMuleRingDetected,
			ISO8583:     telemetry.MapReasonToISO8583(telemetry.CodeMuleRingDetected),
			FraudScore:  0.95,
			Explanation: fmt.Sprintf("Cyclic mule transfer pattern detected: %s", cyclePath),
		}
	}

	// 3. Velocity & Anomaly Calculation
	velocityCount := g.getRecentTransferCount(fromAcc, now)
	deviceCount := g.getDistinctDeviceCount(fromAcc, now)

	var score float64 = 0.05 // Baseline noise

	// Burst velocity risk
	if g.velocityRejectThreshold > 0 && velocityCount >= g.velocityRejectThreshold {
		score += 0.80
	} else if g.velocityWarnThreshold > 0 && velocityCount >= g.velocityWarnThreshold {
		score += 0.50
	} else if g.velocityWarnThreshold > 1 && velocityCount >= g.velocityWarnThreshold/2 {
		score += 0.20
	}

	// Device hopping risk
	if deviceCount >= 3 {
		score += 0.35
	}

	// High value spike risk (heuristic)
	if amount > 500000 { // > $5,000
		score += 0.15
	}

	// Cap score to [0.0, 1.0]
	if score > 1.0 {
		score = 1.0
	}

	// 4. Decision Gate (Threshold >= 0.75)
	if score >= FraudScoreThreshold {
		return FraudDecision{
			Approved:    false,
			ReasonCode:  telemetry.CodeMuleRingDetected,
			ISO8583:     telemetry.MapReasonToISO8583(telemetry.CodeMuleRingDetected),
			FraudScore:  score,
			Explanation: fmt.Sprintf("High velocity cyclic transfer suspected: %d transfers in 60s", velocityCount),
		}
	}

	// Record legitimate/approved event into graph
	event := TransactionEvent{
		TxID:       txID,
		FromAcc:    fromAcc,
		ToAcc:      toAcc,
		DeviceID:   deviceID,
		MerchantID: merchantID,
		IPAddress:  ipAddress,
		Amount:     amount,
		Timestamp:  now,
	}
	g.accountTransfers[fromAcc] = append(g.accountTransfers[fromAcc], event)

	if deviceID != "" {
		if g.accountDevices[fromAcc] == nil {
			g.accountDevices[fromAcc] = make(map[string]time.Time)
		}
		g.accountDevices[fromAcc][deviceID] = now
	}

	if ipAddress != "" {
		if g.accountIPs[fromAcc] == nil {
			g.accountIPs[fromAcc] = make(map[string]time.Time)
		}
		g.accountIPs[fromAcc][ipAddress] = now
	}

	return FraudDecision{
		Approved:    true,
		ReasonCode:  telemetry.CodeApproved,
		ISO8583:     telemetry.MapReasonToISO8583(telemetry.CodeApproved),
		FraudScore:  score,
		Explanation: "Inline screening passed.",
	}
}

// detectCycleBFS performs a 2-hop search to find cycles returning to fromAcc within 60s
func (g *InMemGraphFraudEngine) detectCycleBFS(fromAcc, toAcc string, now time.Time) (bool, string) {
	if toAcc == "" || fromAcc == toAcc {
		return false, ""
	}

	cutoff := now.Add(-SlidingWindowDuration)

	// Hop 1: Check if toAcc has sent funds directly back to fromAcc
	hop1Events := g.accountTransfers[toAcc]
	for _, ev1 := range hop1Events {
		if ev1.Timestamp.After(cutoff) {
			if ev1.ToAcc == fromAcc {
				return true, fmt.Sprintf("%s -> %s -> %s (Direct Cycle)", fromAcc, toAcc, fromAcc)
			}

			// Hop 2: Check if ev1.ToAcc sent funds back to fromAcc
			hop2Events := g.accountTransfers[ev1.ToAcc]
			for _, ev2 := range hop2Events {
				if ev2.Timestamp.After(cutoff) && ev2.ToAcc == fromAcc {
					return true, fmt.Sprintf("%s -> %s -> %s -> %s (2-Hop Mule Cycle)", fromAcc, toAcc, ev1.ToAcc, fromAcc)
				}
			}
		}
	}

	return false, ""
}

func (g *InMemGraphFraudEngine) getRecentTransferCount(accountID string, now time.Time) int {
	cutoff := now.Add(-SlidingWindowDuration)
	count := 0
	for _, ev := range g.accountTransfers[accountID] {
		if ev.Timestamp.After(cutoff) {
			count++
		}
	}
	return count
}

func (g *InMemGraphFraudEngine) getDistinctDeviceCount(accountID string, now time.Time) int {
	cutoff := now.Add(-SlidingWindowDuration)
	count := 0
	for _, lastSeen := range g.accountDevices[accountID] {
		if lastSeen.After(cutoff) {
			count++
		}
	}
	return count
}

// pruneExpiredEvents cleans up events older than 60s to maintain <= 512MB RAM
func (g *InMemGraphFraudEngine) pruneExpiredEvents(now time.Time) {
	cutoff := now.Add(-SlidingWindowDuration)

	for acc, events := range g.accountTransfers {
		valid := events[:0]
		for _, ev := range events {
			if ev.Timestamp.After(cutoff) {
				valid = append(valid, ev)
			}
		}
		if len(valid) == 0 {
			delete(g.accountTransfers, acc)
		} else {
			g.accountTransfers[acc] = valid
		}
	}

	for acc, devices := range g.accountDevices {
		for dev, lastSeen := range devices {
			if lastSeen.Before(cutoff) {
				delete(devices, dev)
			}
		}
		if len(devices) == 0 {
			delete(g.accountDevices, acc)
		}
	}

	for acc, ips := range g.accountIPs {
		for ip, lastSeen := range ips {
			if lastSeen.Before(cutoff) {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(g.accountIPs, acc)
		}
	}
}

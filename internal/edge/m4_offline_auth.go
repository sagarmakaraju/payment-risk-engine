package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"fs2601/internal/fraud"
	"fs2601/internal/telemetry"
)

const (
	MaxOfflineFloorLimitCents int64 = 5000 // $50.00 Max Floor
)

var (
	ErrTokenExpired      = errors.New("offline token expired")
	ErrTokenInvalidSig   = errors.New("invalid cryptographic token signature")
	ErrFloorLimitExceeded= errors.New("transaction amount exceeds maximum floor limit")
	ErrCumulativeExceeded= errors.New("cumulative spent exceeds token ceiling")
	ErrTerminalMismatch  = errors.New("token terminal restriction does not match current POS")
)

// OfflineAuthorizationToken represents an Ed25519-signed offline allowance token
type OfflineAuthorizationToken struct {
	TokenID         string `json:"token_id"`
	AccountID       string `json:"account_id"`
	MaxFloorAmount  int64  `json:"max_floor_amount"` // in cents (<= 5000)
	ExpirationTime  int64  `json:"expiration_time"`  // unix timestamp in seconds
	TerminalID      string `json:"terminal_id"`      // permitted terminal or "*"
	SequenceCounter int64  `json:"sequence_counter"`
	Signature       string `json:"signature"`        // hex-encoded Ed25519 signature
}

// Digest computes the canonical byte sequence for signature verification
func (t *OfflineAuthorizationToken) Digest() []byte {
	raw := fmt.Sprintf("%s:%s:%d:%d:%s:%d",
		t.TokenID, t.AccountID, t.MaxFloorAmount, t.ExpirationTime, t.TerminalID, t.SequenceCounter)
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// TokenAuthority issues and signs offline authorization tokens
type TokenAuthority struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	counter    int64
}

// NewTokenAuthority creates or initializes a cryptographic token authority
func NewTokenAuthority() (*TokenAuthority, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &TokenAuthority{
		publicKey:  pub,
		privateKey: priv,
	}, nil
}

// PublicKey returns the public key required by edge authorizers
func (ta *TokenAuthority) PublicKey() ed25519.PublicKey {
	return ta.publicKey
}

// IssueToken mints a valid offline token for an account with floor ceiling
func (ta *TokenAuthority) IssueToken(accountID string, floorAmount int64, duration time.Duration, terminalID string) (*OfflineAuthorizationToken, error) {
	if floorAmount > MaxOfflineFloorLimitCents {
		floorAmount = MaxOfflineFloorLimitCents
	}

	seq := atomic.AddInt64(&ta.counter, 1)
	tokenID := fmt.Sprintf("TOK-%s-%d-%d", accountID, time.Now().UnixNano(), seq)
	tok := &OfflineAuthorizationToken{
		TokenID:         tokenID,
		AccountID:       accountID,
		MaxFloorAmount:  floorAmount,
		ExpirationTime:  time.Now().Add(duration).Unix(),
		TerminalID:      terminalID,
		SequenceCounter: seq,
	}

	digest := tok.Digest()
	sig := ed25519.Sign(ta.privateKey, digest)
	tok.Signature = hex.EncodeToString(sig)

	return tok, nil
}

// EdgeAuthorizer validates tokens and grants offline authorizations on edge devices
type EdgeAuthorizer struct {
	mu               sync.Mutex
	publicKey        ed25519.PublicKey
	terminalID       string
	spentByToken     map[string]int64 // TokenID -> cumulative cents spent
	sequenceNum      int64
	revocationFilter *fraud.CompactFilter // Feature 2: Cuckoo revocation filter
}

// NewEdgeAuthorizer initializes the edge verification agent
func NewEdgeAuthorizer(pubKey ed25519.PublicKey, terminalID string) *EdgeAuthorizer {
	return &EdgeAuthorizer{
		publicKey:    pubKey,
		terminalID:   terminalID,
		spentByToken: make(map[string]int64),
		sequenceNum:  0,
	}
}

// SetRevocationFilter mounts a compact revocation filter for sub-microsecond edge blocking
func (ea *EdgeAuthorizer) SetRevocationFilter(filter *fraud.CompactFilter) {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	ea.revocationFilter = filter
}

// OfflineAuthDecision captures the outcome of an offline authorization check
type OfflineAuthDecision struct {
	Approved       bool
	ReasonCode     telemetry.ReasonCode
	ISO8583        string
	SequenceNum    int64
	RemainingFloor int64
	Message        string
}

// AuthorizeOffline checks cryptographic validity and floor limits
func (ea *EdgeAuthorizer) AuthorizeOffline(token *OfflineAuthorizationToken, amount int64) OfflineAuthDecision {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	// 0. Check Compact Revocation Filter (Feature 2: Sub-microsecond local edge revocation)
	if ea.revocationFilter != nil {
		if ea.revocationFilter.Contains(token.AccountID) || ea.revocationFilter.Contains(token.TokenID) {
			return OfflineAuthDecision{
				Approved:   false,
				ReasonCode: telemetry.CodeRevokedAccountEdge,
				ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeRevokedAccountEdge),
				Message:    "Account or card token revoked at edge (Lost/Stolen Card).",
			}
		}
	}

	now := time.Now().Unix()

	// 1. Validate Expiration
	if now > token.ExpirationTime {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeOfflineTokenInvalid,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeOfflineTokenInvalid),
			Message:    "Offline authorization token has expired.",
		}
	}

	// 2. Validate Terminal Binding
	if token.TerminalID != "*" && token.TerminalID != ea.terminalID {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeOfflineTokenInvalid,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeOfflineTokenInvalid),
			Message:    fmt.Sprintf("Token restricted to terminal %s (current: %s)", token.TerminalID, ea.terminalID),
		}
	}

	// 3. Verify Cryptographic Ed25519 Signature
	sigBytes, err := hex.DecodeString(token.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeOfflineTokenInvalid,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeOfflineTokenInvalid),
			Message:    "Malformed or tampered token signature.",
		}
	}

	digest := token.Digest()
	if !ed25519.Verify(ea.publicKey, digest, sigBytes) {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeOfflineTokenInvalid,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeOfflineTokenInvalid),
			Message:    "Cryptographic token verification failed.",
		}
	}

	// 4. Validate Single-Transaction Floor Limit ($50 max)
	if amount > token.MaxFloorAmount || amount > MaxOfflineFloorLimitCents {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeFloorLimitExceeded,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeFloorLimitExceeded),
			Message:    fmt.Sprintf("Transaction amount %d cents exceeds floor ceiling %d cents ($50 max)", amount, token.MaxFloorAmount),
		}
	}

	// 5. Validate Cumulative Spent Under This Token
	spent := ea.spentByToken[token.TokenID]
	if spent+amount > token.MaxFloorAmount {
		return OfflineAuthDecision{
			Approved:   false,
			ReasonCode: telemetry.CodeFloorLimitExceeded,
			ISO8583:    telemetry.MapReasonToISO8583(telemetry.CodeFloorLimitExceeded),
			Message:    fmt.Sprintf("Cumulative spent %d + %d exceeds token allowance %d", spent, amount, token.MaxFloorAmount),
		}
	}

	// Authorization Granted
	ea.spentByToken[token.TokenID] += amount
	ea.sequenceNum++

	return OfflineAuthDecision{
		Approved:       true,
		ReasonCode:     telemetry.CodeApproved,
		ISO8583:        telemetry.MapReasonToISO8583(telemetry.CodeApproved),
		SequenceNum:    ea.sequenceNum,
		RemainingFloor: token.MaxFloorAmount - ea.spentByToken[token.TokenID],
		Message:        "Offline authorization granted under cryptographic floor limit.",
	}
}

// ResetSpentCache clears local token spending cache (e.g. on reconciliation)
func (ea *EdgeAuthorizer) ResetSpentCache() {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	ea.spentByToken = make(map[string]int64)
}

// MarshalToken helper serializes token to JSON
func MarshalToken(tok *OfflineAuthorizationToken) ([]byte, error) {
	return json.Marshal(tok)
}

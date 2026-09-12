package fraud

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

const (
	EpochIntervalSeconds int64 = 30 // 30-second rotating window
	MaxEpochSkewSeconds  int64 = 60 // Max 60-second skew tolerance
)

// DynamicQRPayload contains dynamic QR parameters with asymmetric rotating epoch signature
type DynamicQRPayload struct {
	MerchantID string `json:"merchant_id"`
	TerminalID string `json:"terminal_id"`
	EpochSalt  int64  `json:"epoch_salt"` // Unix timestamp rounded to 30s
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`  // Hex-encoded Ed25519 signature
}

// CurrentEpochSalt returns the current epoch salt rounded to 30s
func CurrentEpochSalt() int64 {
	now := time.Now().Unix()
	return (now / EpochIntervalSeconds) * EpochIntervalSeconds
}

// ComputeQRDigest creates the canonical digest for signing and verification
func ComputeQRDigest(merchantID, terminalID string, epochSalt int64, nonce string) []byte {
	raw := fmt.Sprintf("%s||%s||%d||%s", merchantID, terminalID, epochSalt, nonce)
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// SignDynamicQR generates a signed dynamic QR payload using the terminal's Ed25519 private key
func SignDynamicQR(terminalPrivKey ed25519.PrivateKey, merchantID, terminalID string) (DynamicQRPayload, error) {
	epoch := CurrentEpochSalt()

	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return DynamicQRPayload{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	digest := ComputeQRDigest(merchantID, terminalID, epoch, nonce)
	sig := ed25519.Sign(terminalPrivKey, digest)

	return DynamicQRPayload{
		MerchantID: merchantID,
		TerminalID: terminalID,
		EpochSalt:  epoch,
		Nonce:      nonce,
		Signature:  hex.EncodeToString(sig),
	}, nil
}

// VerifyDynamicQR validates the dynamic QR payload against the terminal's Ed25519 public key
// Returns (valid bool, failureReason string)
func VerifyDynamicQR(payload DynamicQRPayload, terminalPubKey ed25519.PublicKey) (bool, string) {
	now := time.Now().Unix()

	// 1. Check Epoch Freshness (|now - EpochSalt| <= 60 seconds)
	skew := int64(math.Abs(float64(now - payload.EpochSalt)))
	if skew > MaxEpochSkewSeconds {
		return false, fmt.Sprintf("Dynamic QR epoch expired (skew %d seconds > %d seconds max)", skew, MaxEpochSkewSeconds)
	}

	// 2. Decode signature
	sigBytes, err := hex.DecodeString(payload.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false, "Malformed or invalid signature format"
	}

	// 3. Verify Ed25519 signature
	digest := ComputeQRDigest(payload.MerchantID, payload.TerminalID, payload.EpochSalt, payload.Nonce)
	if !ed25519.Verify(terminalPubKey, digest, sigBytes) {
		return false, "Ed25519 signature mismatch: physical QR overlay sticker tampering detected"
	}

	return true, ""
}
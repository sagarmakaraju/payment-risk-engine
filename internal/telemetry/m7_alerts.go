package telemetry

import "encoding/json"

// ReasonCode defines standard explainable failure and status codes
type ReasonCode string

const (
	CodeApproved             ReasonCode = "APPROVED"
	CodeInsufficientFunds    ReasonCode = "INSUFFICIENT_FUNDS"
	CodeQRMismatch           ReasonCode = "QR_MISMATCH"
	CodeMuleRingDetected     ReasonCode = "MULE_RING_DETECTED"
	CodeFloorLimitExceeded   ReasonCode = "FLOOR_LIMIT_EXCEEDED"
	CodeOfflineTokenInvalid  ReasonCode = "OFFLINE_TOKEN_INVALID"
	CodeDuplicateTransaction ReasonCode = "DUPLICATE_TRANSACTION"
	CodeSettlementDeficit    ReasonCode = "SETTLEMENT_DEFICIT"
	CodeRevokedAccountEdge   ReasonCode = "ERR_REVOKED_ACCOUNT_EDGE"
	CodeQRTampering          ReasonCode = "ERR_QR_TAMPERING"
	CodeReconDeficitChargedToReserve ReasonCode = "RECON_DEFICIT_CHARGED_TO_RESERVE"
	CodeSystemError          ReasonCode = "SYSTEM_ERROR"
)

// MapReasonToISO8583 maps business logic failure codes to ISO-8583 response codes
func MapReasonToISO8583(code ReasonCode) string {
	switch code {
	case CodeApproved:
		return "00" // Approved
	case CodeInsufficientFunds:
		return "51" // Insufficient funds
	case CodeQRMismatch:
		return "57" // Transaction not permitted / QR tamper
	case CodeQRTampering:
		return "59" // Suspected fraud / Dynamic QR tampering
	case CodeMuleRingDetected:
		return "59" // Suspected fraud / Mule ring
	case CodeFloorLimitExceeded:
		return "61" // Exceeds withdrawal amount limit / Floor ceiling
	case CodeOfflineTokenInvalid:
		return "63" // Security violation / Token expired or signature invalid
	case CodeRevokedAccountEdge:
		return "41" // Lost/Stolen card / Revoked account at edge
	case CodeDuplicateTransaction:
		return "94" // Duplicate transmission
	case CodeSettlementDeficit, CodeReconDeficitChargedToReserve:
		return "96" // System error / Deficit recorded or charged to reserve
	default:
		return "05" // Do not honor / General decline
	}
}

// PaymentResponse defines standard API payment authorization response
type PaymentResponse struct {
	Status         string     `json:"status"`
	ReasonCode     ReasonCode `json:"reason_code"`
	ISO8583        string     `json:"iso8583"`
	Message        string     `json:"message"`
	TxID           string     `json:"tx_id,omitempty"`
	Amount         int64      `json:"amount,omitempty"`
	AccountID      string     `json:"account_id,omitempty"`
	FraudScore     float64    `json:"fraud_score,omitempty"`
	IsOffline      bool       `json:"is_offline,omitempty"`
	OfflineTokenID string     `json:"offline_token_id,omitempty"`
}

// NewApprovalResponse formats a successful authorization response
func NewApprovalResponse(txID string, accountID string, amount int64, fraudScore float64) PaymentResponse {
	return PaymentResponse{
		Status:     "APPROVED",
		ReasonCode: CodeApproved,
		ISO8583:    "00",
		Message:    "Transaction authorized successfully.",
		TxID:       txID,
		AccountID:  accountID,
		Amount:     amount,
		FraudScore: fraudScore,
		IsOffline:  false,
	}
}

// NewOfflineApprovalResponse formats an offline approved payment response
func NewOfflineApprovalResponse(txID string, accountID string, amount int64, tokenID string) PaymentResponse {
	return PaymentResponse{
		Status:         "OFFLINE_AUTHORIZED",
		ReasonCode:     CodeApproved,
		ISO8583:        "00",
		Message:        "Transaction authorized offline against cryptographic floor limit.",
		TxID:           txID,
		AccountID:      accountID,
		Amount:         amount,
		IsOffline:      true,
		OfflineTokenID: tokenID,
	}
}

// NewDeclineResponse formats a machine-readable explainable decline response
func NewDeclineResponse(code ReasonCode, message string, fraudScore float64) PaymentResponse {
	return PaymentResponse{
		Status:     "DECLINED",
		ReasonCode: code,
		ISO8583:    MapReasonToISO8583(code),
		Message:    message,
		FraudScore: fraudScore,
	}
}

// ToJSON serializes the payment response
func (p PaymentResponse) ToJSON() []byte {
	b, _ := json.Marshal(p)
	return b
}

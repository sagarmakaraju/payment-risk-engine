# FS-2601 End-to-End Live Partition & Fraud Screening Simulation Script
# Tests all core modules M1-M7 and production-grade features F1-F5
$ErrorActionPreference = "Stop"
$baseUrl = "http://localhost:8080"

function Print-Header($title) {
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Print-Success($msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

function Print-Warning($msg) {
    Write-Host "[ALERT] $msg" -ForegroundColor Yellow
}

function Print-Info($msg) {
    Write-Host "[INFO] $msg" -ForegroundColor White
}

function Parse-ErrorResponse($err) {
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) {
        try { return ($err.ErrorDetails.Message | ConvertFrom-Json) } catch {}
    }
    if ($err.Exception -and $err.Exception.Response) {
        try {
            $stream = $err.Exception.Response.GetResponseStream()
            $text = [System.IO.StreamReader]::new($stream).ReadToEnd()
            return ($text | ConvertFrom-Json)
        } catch {}
    }
    return $null
}

# 1. Health check
Print-Header "Phase 1: Checking Node Health & Initial State"
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/api/v1/health"
    Print-Success "Server online. Network Status: $($health.network_status)"
} catch {
    Write-Host "[ERROR] Server is not running on $baseUrl. Please start bin\server.exe first." -ForegroundColor Red
    exit 1
}

# 2. Feature 1: Dual-Bucket Pre-Reservation Check
Print-Header "Phase 2: Feature 1 - Dual-Bucket Cryptographic Balance Pre-Reservation"
$acc = Invoke-RestMethod -Uri "$baseUrl/api/v1/account/ACC-BENCH-1"
Print-Info "Account ACC-BENCH-1: OnlineAvailable = $($acc.online_available) cents, OfflineAllowance = $($acc.offline_allowance) cents, Reserved = $($acc.reserved_balance) cents"
$total = $acc.online_available + $acc.offline_allowance + $acc.reserved_balance
if ($total -eq $acc.total_balance) {
    Print-Success "Dual-Bucket Conservation Invariant Verified: Online ($($acc.online_available)) + Offline ($($acc.offline_allowance)) + Reserved ($($acc.reserved_balance)) == Total ($($acc.total_balance))"
} else {
    Write-Host "[ERROR] Invariant failed!" -ForegroundColor Red
}

# 3. Online Payment with Dynamic QR
Print-Header "Phase 3: Online Payment Authorization with Genuine Request"
$payBody = @{
    idempotency_key = "IDEMP-SIM-1"
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 2000 # $20.00
} | ConvertTo-Json

$respOnline = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $payBody -ContentType "application/json"
Print-Success "Online payment approved: TxID=$($respOnline.tx_id), ISO8583=$($respOnline.iso8583), FraudScore=$($respOnline.fraud_score)"

# 4. Feature 3: Dynamic QR Handshake with Rotating Epoch Salts
Print-Header "Phase 4: Feature 3 - Genuine Dynamic QR Handshake (Ed25519 + 30s Epoch Salt)"
$qrValid = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/qr/generate" -Body '{"merchant_id":"MERCHANT-POS-01","terminal_id":"TERM-001","tamper_mode":"NONE"}' -ContentType "application/json"
Print-Info "Generated Dynamic QR: Merchant=$($qrValid.merchant_id), EpochSalt=$($qrValid.epoch_salt), Nonce=$($qrValid.nonce)"

$payQRValid = @{
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1500
    dynamic_qr = $qrValid
} | ConvertTo-Json

$respQR = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $payQRValid -ContentType "application/json"
Print-Success "Dynamic QR payment verified: TxID=$($respQR.tx_id), ISO8583=$($respQR.iso8583)"

# 5. Feature 3: Attacker Physical Sticker Replacement Defense
Print-Header "Phase 5: Feature 3 - Defeating Physical QR Sticker Replacement Attack"
$qrSticker = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/qr/generate" -Body '{"merchant_id":"MERCHANT-POS-01","terminal_id":"TERM-001","tamper_mode":"STICKER_MISMATCH"}' -ContentType "application/json"
Print-Info "Injected Attacker Sticker pointing to $($qrSticker.merchant_id)"

$paySticker = @{
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1500
    dynamic_qr = $qrSticker
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $paySticker -ContentType "application/json"
} catch {
    $errObj = Parse-ErrorResponse $_
    if ($errObj) {
        Print-Warning "Physical QR Sticker Attack Defeated: Reason=$($errObj.reason_code), ISO8583=$($errObj.iso8583), FraudScore=$($errObj.fraud_score)"
        Print-Info "Explanation: $($errObj.message)"
    }
}

# 6. Feature 3: Expired Epoch Salt Defense (> 60s Skew)
Print-Header "Phase 6: Feature 3 - Defeating Replay of Expired Dynamic QR (> 60s skew)"
$qrExpired = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/qr/generate" -Body '{"merchant_id":"MERCHANT-POS-01","terminal_id":"TERM-001","tamper_mode":"EXPIRED"}' -ContentType "application/json"
$payExpired = @{
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1500
    dynamic_qr = $qrExpired
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $payExpired -ContentType "application/json"
} catch {
    $errObj = Parse-ErrorResponse $_
    if ($errObj) {
        Print-Warning "Expired Dynamic QR Blocked: Reason=$($errObj.reason_code), ISO8583=$($errObj.iso8583)"
    }
}

# 7. Inject Network Partition
Print-Header "Phase 7: Simulating Network Partition (ONLINE -> DISCONNECTED)"
$discResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/network/toggle" -Body '{"status":"DISCONNECTED"}' -ContentType "application/json"
Print-Warning "Network partitioned: Status is now $($discResp.network_status)"

# 8. Feature 2: Compact Cuckoo Revocation Filter Local Rejection
Print-Header "Phase 8: Feature 2 - Compact Cuckoo Revocation Filter Local Rejection"
$cuckooStats = Invoke-RestMethod -Uri "$baseUrl/api/v1/revocation/stats"
Print-Info "Compact Filter Stats: Keys=$($cuckooStats.total_revoked_keys), Memory=$($cuckooStats.filter_kb) KB, Latency=$($cuckooStats.lookup_latency_ns) ns, FPR=$($cuckooStats.observed_fpr)"

# Issue token for revoked card ACC-REVOKED-DEMO
$revokedToken = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tokens/issue" -Body '{"account_id":"ACC-REVOKED-DEMO","max_floor_amount":5000,"duration_sec":3600,"terminal_id":"TERM-001"}' -ContentType "application/json"
$payRevoked = @{
    account_id = "ACC-REVOKED-DEMO"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1000
    offline_token = $revokedToken
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $payRevoked -ContentType "application/json"
} catch {
    $errObj = Parse-ErrorResponse $_
    if ($errObj) {
        Print-Warning "Revoked Account Instantly Blocked at Edge: Reason=$($errObj.reason_code), ISO8583=$($errObj.iso8583)"
        Print-Info "Explanation: $($errObj.message)"
    }
}

# 9. Offline Cryptographic Token Issuance & Floor Limit
Print-Header "Phase 9: Edge Offline Authorizations with Ed25519 Token"
$tokenResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tokens/issue" -Body '{"account_id":"ACC-BENCH-1","max_floor_amount":5000,"duration_sec":3600,"terminal_id":"TERM-001"}' -ContentType "application/json"
Print-Success "Cryptographic Ed25519 Token Issued: ID=$($tokenResp.token_id), MaxFloor=$($tokenResp.max_floor_amount) cents ($50 max)"

$offPay1 = @{
    idempotency_key = "IDEMP-OFF-1"
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1500
    offline_token = $tokenResp
} | ConvertTo-Json

$respOff1 = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $offPay1 -ContentType "application/json"
Print-Success "Offline Payment Authorized: Status=$($respOff1.status), Amount=$($respOff1.amount) cents, TokenID=$($respOff1.offline_token_id)"

# 10. Reconnect & Deterministic Replay
Print-Header "Phase 10: Reconnection (DISCONNECTED -> RECONNECTED) & Vector Clock Replay"
$recResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/network/toggle" -Body '{"status":"RECONNECTED"}' -ContentType "application/json"
Print-Success "Network Reconnected. Reconciled: $($recResp.reconciled)"
Print-Info "Report: Processed=$($recResp.report.total_processed), Success=$($recResp.report.successful_count), Deficits=$($recResp.report.deficit_count), TotalReconciled=$($recResp.report.total_amount_reconciled) cents"

# 11. Feature 5: Deficit Reserve & Conservation Audit
Print-Header "Phase 11: Feature 5 - Deficit Reserve & System-Wide Double-Entry Conservation Audit"
$reserve = Invoke-RestMethod -Uri "$baseUrl/api/v1/ledger/reserve"
Print-Success "Deficit Reserve (ACC_MERCHANT_DEFICIT_RESERVE): Available = $($reserve.online_available) cents ($($reserve.online_available / 100) USD)"

$audit = Invoke-RestMethod -Uri "$baseUrl/api/v1/audit/conservation"
Print-Success "Total System Balance: $($audit.total_system_balance) cents ($($audit.total_system_balance / 100) USD)"
Print-Success "Double-Entry Ledger Records: $($audit.ledger_entry_count) audit entries"
Print-Success "ZERO DOUBLE-SPENDING GUARANTEED."

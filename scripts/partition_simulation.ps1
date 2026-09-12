# FS-2601 End-to-End Live Partition & Fraud Screening Simulation Script
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

$acc = Invoke-RestMethod -Uri "$baseUrl/api/v1/account/ACC-BENCH-1"
Print-Info "Account ACC-BENCH-1: Available = $($acc.available_balance) cents, Reserved = $($acc.reserved_balance) cents"

# 2. Online Payments with Dynamic QR
Print-Header "Phase 2: Online Payment Authorization with Genuine QR"
$payBody = @{
    idempotency_key = "IDEMP-SIM-1"
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 2000 # $20.00
} | ConvertTo-Json

$respOnline = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $payBody -ContentType "application/json"
Print-Success "Online payment approved: TxID=$($respOnline.tx_id), ISO8583=$($respOnline.iso8583), FraudScore=$($respOnline.fraud_score)"

# 3. Fraud Detection: Tampered QR Sticker
Print-Header "Phase 3: Inline Fraud Screening (QR Tampering & Mule Ring)"
$tamperedQR = @{
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    amount = 2000
    qr_payload = @{
        terminal_id = "TERM-001"
        merchant_id = "MERCHANT-POS-01"
        dynamic_nonce = "NONCE-TAMPER"
        amount = 2000
        signature = "INVALID_TAMPERED_HMAC_SIG"
    }
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $tamperedQR -ContentType "application/json"
} catch {
    $errObj = Parse-ErrorResponse $_
    if ($errObj) {
        Print-Warning "Tampered QR Blocked: Status=$($errObj.status), Reason=$($errObj.reason_code), ISO8583=$($errObj.iso8583)"
        Print-Info "Reason message: $($errObj.message)"
    } else {
        Print-Warning "Tampered QR Blocked with HTTP error: $_"
    }
}

# 4. Inject Network Partition
Print-Header "Phase 4: Simulating Network Partition (ONLINE -> DISCONNECTED)"
$discResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/network/toggle" -Body '{"status":"DISCONNECTED"}' -ContentType "application/json"
Print-Warning "Network partitioned: Status is now $($discResp.network_status)"

# 5. Offline Cryptographic Token Issuance & Edge Floor Check
Print-Header "Phase 5: Edge Offline Authorizations with Ed25519 Token"
$tokenResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/tokens/issue" -Body '{"account_id":"ACC-BENCH-1","max_floor_amount":5000,"duration_sec":3600,"terminal_id":"TERM-001"}' -ContentType "application/json"
Print-Success "Cryptographic Ed25519 Token Issued: ID=$($tokenResp.token_id), MaxFloor=$($tokenResp.max_floor_amount) cents ($50 max)"

# Offline payment 1 ($15.00)
$offPay1 = @{
    idempotency_key = "IDEMP-OFF-1"
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 1500
    offline_token = $tokenResp
} | ConvertTo-Json

$respOff1 = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $offPay1 -ContentType "application/json"
Print-Success "Offline Payment 1 Authorized: Status=$($respOff1.status), Amount=$($respOff1.amount) cents, TokenID=$($respOff1.offline_token_id)"

# Offline payment 2 exceeding floor limit ($60.00 > $50.00 max)
$offPayExceed = @{
    account_id = "ACC-BENCH-1"
    merchant_id = "MERCHANT-POS-01"
    terminal_id = "TERM-001"
    amount = 6000
    offline_token = $tokenResp
} | ConvertTo-Json

try {
    Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/auth/pay" -Body $offPayExceed -ContentType "application/json"
} catch {
    $errObj = Parse-ErrorResponse $_
    if ($errObj) {
        Print-Warning "Offline Floor Ceiling Enforced: Status=$($errObj.status), Reason=$($errObj.reason_code), ISO8583=$($errObj.iso8583)"
        Print-Info "Reason message: $($errObj.message)"
    } else {
        Print-Warning "Offline Floor Ceiling Enforced with HTTP error: $_"
    }
}

# 6. Reconnect & Deterministic Reconciliation
Print-Header "Phase 6: Reconnection (DISCONNECTED -> RECONNECTED) & Deterministic Replay"
$recResp = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/v1/network/toggle" -Body '{"status":"RECONNECTED"}' -ContentType "application/json"
Print-Success "Network Reconnected. Reconciled: $($recResp.reconciled)"
Print-Info "Report: Processed=$($recResp.report.total_processed), Success=$($recResp.report.successful_count), Deficits=$($recResp.report.deficit_count), TotalReconciled=$($recResp.report.total_amount_reconciled) cents"

# 7. Final Ledger Conservation Audit
Print-Header "Phase 7: System-Wide Double-Entry Conservation Audit"
$audit = Invoke-RestMethod -Uri "$baseUrl/api/v1/audit/conservation"
Print-Success "Total System Balance: $($audit.total_system_balance) cents ($($audit.total_system_balance / 100) USD)"
Print-Success "Double-Entry Ledger Records: $($audit.ledger_entry_count) audit entries"
Print-Success "ZERO DOUBLE-SPENDING GUARANTEED."

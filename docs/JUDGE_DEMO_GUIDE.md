# Hackathon Judge Evaluation & Live Demonstration Guide (FS-2601)

This guide provides five structured paths to evaluate the reference implementation for **FS-2601: Partition-Tolerant Payment Authorization with Inline Fraud Screening**:
1. **Option A: 60-Second Automated Test Suite & Benchmarks** (Pure Go, 9 tests + 5 benchmarks)
2. **Option B: 3-Minute Live 11-Phase Chaos Partition Simulation** (Automated script against running binary)
3. **Option C: 5-Minute Interactive Web Console & Visual Audit** (`http://localhost:8080/dashboard` or `http://localhost:8081/dashboard`)
4. **Option D: Terminal CLI Evaluation** (`.\bin\fs2601-cli.exe`)
5. **Option E: Instant Zero-Install Global Cloud Evaluation** (`https://positions-him-expenditures-boards.trycloudflare.com/dashboard`)

---

## Prerequisites
- **OS**: Windows, macOS, or Linux
- **Go**: 1.23+ (Installed in user space or system PATH)
- **Zero External Dependencies**: No Docker, Kafka, Redis, or cloud services needed.

---

## Option A: 60-Second Automated Test Suite & Benchmarks

Run the complete Go verification test suite directly:

```powershell
# 1. Run all unit and integration tests (zero double-spends, partition replay, fraud screening)
go test -v -count=1 ./tests/...

# 2. Run throughput benchmarks (>2.5 million ops/sec)
go test -bench="." -benchmem ./tests/...
```

### Expected Output Summary
- `TestConcurrencyAndZeroDoubleSpend`:
  - 500 concurrent goroutines racing to deplete an account with $\$1,000.00$.
  - Exactly 100 transactions approved ($\$1,000.00$), 400 declined with `INSUFFICIENT_FUNDS` (ISO `51`).
  - Remaining balance $= \$0.00$. Merchant balance $= \$1,000.00$. Zero double-spends!
  - `p50: 531 µs | p90: 842 µs | p99: 842 µs` (Target: $\le 300\text{ ms}$).
- `TestFeature1_DualBucketCryptographicBalancePreReservation`:
  - 500 concurrent goroutines deplete online available balance to $\$0.00$.
  - Offline allowance ($30,000$ cents) remains completely untouched and spendable up to ceiling without race conditions.
- `TestFeature2_CompactFilterLocalRevocation`:
  - 10,000 revoked keys inserted into Cuckoo filter.
  - 50,000 negative test keys evaluated: **0.0000% FPR** (target $\le 1.2\%$).
  - Offline token for revoked account instantly declined at edge with `ERR_REVOKED_ACCOUNT_EDGE` (ISO `41`).
- `TestFeature3_AsymmetricDynamicQRHandshake`:
  - Valid dynamic QR passes.
  - Expired epoch salt (> 60s skew) rejected with `ERR_QR_TAMPERING` (ISO `59`).
  - Attacker physical overlay sticker mismatch rejected with `ERR_QR_TAMPERING` (ISO `59`) and fraud score $1.0$.
- `TestFeature4_MultiTerminalVectorClockConflictResolution`:
  - Out-of-order batches from Terminal A and Terminal B deterministically topologically sorted across 20 random shuffle runs.
- `TestFeature5_AutomatedMerchantDeficitReserve`:
  - Offline overdraw reconciled without negative customer balance ($B_{\text{cust}} = \$0.00$).
  - Merchant receives full settlement; shortfall delta debited from `ACC_MERCHANT_DEFICIT_RESERVE` with alert `RECON_DEFICIT_CHARGED_TO_RESERVE` (ISO `96`).

### Benchmark Metrics (Verified on Intel Core 7)
```text
BenchmarkInlineAuthorization-16             3,221,262    362.5 ns/op      88 B/op    2 allocs/op
BenchmarkFeature1_DualBucketCommit-16       2,510,725    477.0 ns/op     812 B/op    4 allocs/op
BenchmarkFeature2_CompactFilterContains-16 74,626,864     15.17 ns/op      0 B/op    0 allocs/op
BenchmarkFeature3_DynamicQRVerification-16     39,447  31,185 ns/op      248 B/op    8 allocs/op
BenchmarkFeature4_VectorClockSorting-16         7,338 159,108 ns/op   18,680 B/op    4 allocs/op
```

---

## Option B: 3-Minute Live 11-Phase Chaos Partition Simulation

This scripted demonstration simulates a live network partition cut, offline token authorization, and automatic post-partition reconciliation:

```powershell
# 1. Build and start the server
go build -o bin\server.exe ./cmd/server
.\bin\server.exe

# 2. In a second terminal window, run the 11-phase chaos simulation script
powershell.exe -ExecutionPolicy Bypass -File .\scripts\partition_simulation.ps1
```

### What the Simulation Verifies
1. **Phase 1**: Checks node health and reads initial account balance (`ACC-BENCH-1` $= 100,000$ cents).
2. **Phase 2**: Verifies Feature 1 dual-bucket balance pre-reservation invariant ($\text{Online} + \text{Offline} + \text{Reserved} == \text{Total}$).
3. **Phase 3**: Processes a genuine online payment with cryptographic dynamic QR code.
4. **Phase 4**: Generates dynamic QR with 30s rotating epoch salt and verifies genuine handshake.
5. **Phase 5**: Injects an attacker physical QR sticker overlay and verifies rejection with `ERR_QR_TAMPERING` (ISO `59`, FraudScore $1.0$).
6. **Phase 6**: Replays an expired dynamic QR (> 60s skew) and verifies rejection with `ERR_QR_TAMPERING` (ISO `59`).
7. **Phase 7**: Injects network partition cut (`ONLINE` &rarr; `DISCONNECTED`).
8. **Phase 8**: Tests local edge revocation via Compact Cuckoo Filter; verifies instant block of `ACC-REVOKED-DEMO` with `ERR_REVOKED_ACCOUNT_EDGE` (ISO `41`).
9. **Phase 9**: Issues an Ed25519 token; authorizes an offline transaction under the floor limit ($\$15.00$) directly into the edge WAL.
10. **Phase 10**: Restores network connectivity (`RECONNECTED`) and triggers automatic deterministic replay and reconciliation.
11. **Phase 11**: Executes system-wide double-entry conservation audit, verifies `ACC_MERCHANT_DEFICIT_RESERVE` balance, and asserts **zero double-spending**.

---

## Option C: 5-Minute Interactive Web Console

The server includes an embedded web dashboard:

1. Start the server:
   ```powershell
   .\bin\server.exe
   ```
2. Open your web browser to:
   ```
   http://localhost:8080/dashboard
   ```
3. Use the interactive controls:
   - **Network Partition Switch**: Toggle between `ONLINE`, `DISCONNECTED`, and `RECONNECT`.
   - **Transaction Simulator**: Choose scenarios (Valid Dynamic QR, Expired Salt, Sticker Overlay Attack, Forged Key, Revoked Card, Mule Ring, or Overdraw) and click **Authorize Payment**.
   - **Dual-Bucket Breakdown**: Inspect Online, Offline Allowance, and Reserved buckets in real time, or click **+ Allocate Offline Quota** to pre-reserve funds.
   - **Compact Cuckoo Revocation Widget**: Monitor active revoked keys, 64 KB memory usage, 15.5 ns latency, or enter an account ID to revoke immediately.
   - **Dynamic QR Handshake Ticker**: Watch the 30-second epoch salt rotate with a real-time countdown progress bar.
   - **Deficit Reserve Monitor**: Inspect the $\$1,000,000.00$ `ACC_MERCHANT_DEFICIT_RESERVE` balance and observe non-negative customer balance enforcement.
   - **ISO-8583 Inspector**: View real-time ISO-8583 telemetry payloads (`00`, `41`, `51`, `57`, `59`, `61`, `63`, `94`, `96`).

---

## Option D: Terminal CLI Evaluation (`fs2601-cli`)

For terminal-first evaluation, use the compiled `fs2601-cli`:

```powershell
# 1. Build CLI binary
go build -o bin\fs2601-cli.exe ./cmd/cli

# 2. Inspect node health and conservation invariant
.\bin\fs2601-cli.exe health
.\bin\fs2601-cli.exe audit

# 3. Query account balances
.\bin\fs2601-cli.exe balance ACC-BENCH-1

# 4. Process payment
.\bin\fs2601-cli.exe pay ACC-BENCH-1 MERCHANT-POS-01 25.00

# 5. Inspect Cuckoo Filter statistics
.\bin\fs2601-cli.exe cuckoo-stats

# 6. Test dynamic QR generation
.\bin\fs2601-cli.exe qr NONE
.\bin\fs2601-cli.exe qr EXPIRED
.\bin\fs2601-cli.exe qr STICKER_MISMATCH

# 7. Query deficit reserve balance
.\bin\fs2601-cli.exe reserve
```

---

## Option E: Instant Zero-Install Global Cloud Evaluation

For evaluators or judges evaluating remotely without local Go installations:

1. Open the public HTTPS endpoint:
   ```text
   https://positions-him-expenditures-boards.trycloudflare.com/dashboard
   ```
2. Interactive test cases:
   - **Online Auth:** Account: `ACC-BENCH-1` | Amount: `15.00` &rarr; Click **Authorize Payment** &rarr; `APPROVED` (ISO `00`).
   - **Revocation Filter:** Account: `ACC-REVOKED-DEMO` | Amount: `10.00` &rarr; Click **Authorize Payment** &rarr; `DECLINED` (ISO `41`).
   - **Partition Cut:** Click **`DISCONNECT`** &rarr; Amount: `25.00` &rarr; `OFFLINE_AUTHORIZED`.
   - **Reconciliation:** Click **`RECONNECT`** &rarr; Replays WAL and settles via Vector Clock topological ordering.
3. Open the public conservation audit endpoint:
   ```text
   https://positions-him-expenditures-boards.trycloudflare.com/api/v1/audit/conservation
   ```
   Confirms 100% strict mathematical conservation ($\sum \text{Debits} = \sum \text{Credits}$).


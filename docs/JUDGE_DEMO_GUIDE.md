# Hackathon Judge Evaluation & Live Demonstration Guide (FS-2601)

This guide provides three structured paths to evaluate the reference implementation for **FS-2601: Partition-Tolerant Payment Authorization with Inline Fraud Screening**:
1. **Option A: 60-Second Test Suite & Benchmarks**
2. **Option B: 3-Minute Automated Chaos Partition Simulation**
3. **Option C: 5-Minute Interactive Web Console & Visual Audit**

---

## Prerequisites
- **OS**: Windows, macOS, or Linux
- **Go**: 1.23+ (Installed in user space or system PATH)
- **Optional**: Python 3.8+ (for async benchmark client)

---

## Option A: 60-Second Test Suite & Benchmarks

Run the complete Go verification test suite directly:

```powershell
# 1. Run all unit and integration tests (zero double-spends, partition replay, fraud screening)
go test -v -count=1 ./tests

# 2. Run throughput benchmarks (>2.5 million ops/sec)
go test -bench='.' -benchmem ./tests
```

### Expected Output Summary
- `TestConcurrencyAndZeroDoubleSpend`:
  - 500 concurrent goroutines racing to deplete an account with $\$1,000.00$.
  - Exactly 100 transactions approved ($\$1,000.00$), 400 declined with `INSUFFICIENT_FUNDS` (ISO `51`).
  - Remaining balance $= \$0.00$. Merchant balance $= \$1,000.00$. Zero double-spends!
  - `p50: 521 µs | p90: 1.11 ms | p99: 1.11 ms` (Target: $\le 300\text{ ms}$).
- `TestNetworkPartitionAndDeterministicReconciliation`:
  - 10 online transactions authorized.
  - Network cut to `DISCONNECTED`.
  - 50 offline transactions authorized with Ed25519 tokens ($\le \$50.00$ floor) and written to edge disk WAL with CRC32 checksums and synchronous `fsync`.
  - Transaction exceeding floor ($\$60 > \$50$) declined with `FLOOR_LIMIT_EXCEEDED` (ISO `61`).
  - Network restored to `RECONNECTED`: deterministic reconciliation replayed and matched core balance with $100\%$ conservation.
- `TestFraudEngineInlineVerification`:
  - Dynamic QR tampering rejected with `QR_MISMATCH` (ISO `57`).
  - Cyclic mule transfer ($A \to B \to C \to A$) rejected with `MULE_RING_DETECTED` (ISO `59`).
  - False positive rate $= 0.00\%$ over 1,000 baseline transactions (Target: $\le 1.2\%$).

---

## Option B: 3-Minute Automated Chaos Partition Simulation

This scripted demonstration simulates a live network partition cut, offline token authorization, and automatic post-partition reconciliation:

```powershell
# 1. Build and start the server
go build -o bin\server.exe ./cmd/server
.\bin\server.exe

# 2. In a second terminal window, run the chaos simulation script
powershell.exe -ExecutionPolicy Bypass -File .\scripts\partition_simulation.ps1
```

### What the Simulation Verifies
1. **Phase 1**: Checks node health and reads initial account balance (`ACC-BENCH-1` $= 100,000$ cents).
2. **Phase 2**: Processes a genuine online payment with cryptographic dynamic QR code.
3. **Phase 3**: Injects a tampered dynamic QR code sticker and verifies instant rejection with `QR_MISMATCH` (ISO `57`).
4. **Phase 4**: Injects network partition cut (`ONLINE` &rarr; `DISCONNECTED`).
5. **Phase 5**: Issues an Ed25519 token; authorizes an offline transaction under the floor limit ($\$15.00$) directly into the edge WAL; rejects an offline transaction exceeding the floor limit ($\$60.00 > \$50.00$) with `FLOOR_LIMIT_EXCEEDED` (ISO `61`).
6. **Phase 6**: Restores network connectivity (`RECONNECTED`) and triggers automatic deterministic replay and reconciliation.
7. **Phase 7**: Executes system-wide double-entry conservation audit and asserts **zero double-spending**.

---

## Option C: 5-Minute Interactive Web Console

The server includes an embedded web dashboard:

1. Start the server:
   ```powershell
   .\bin\server.exe
   ```
2. Open your web browser to:
   ```
   http://localhost:8080/
   ```
3. Use the interactive controls:
   - **Network Partition Switch**: Toggle between `ONLINE`, `DISCONNECTED`, and `RECONNECT`.
   - **Transaction Simulator**: Choose scenarios (Genuine, Tampered QR, Cyclic Mule Chain, or Overdraw) and click **Authorize Payment**.
   - **ISO-8583 Inspector**: View the real-time ISO-8583 telemetry payload (`00`, `51`, `57`, `59`, `61`, `63`, `94`, `96`).
   - **Edge Floor Meter**: Issue an Ed25519 token and watch the $\$50.00$ floor limit meter update in real time.
   - **Conserving Ledger Visualizer**: Watch available and reserved balances update atomically with zero balance loss.

---

## Option D: Python Async Benchmark (500 Concurrency)

Run the Python concurrency benchmark against the live server:

```powershell
python .\scripts\benchmark_concurrency.py
```

Outputs average, p50, p90, and p99 latencies, along with double-entry conservation assertions.

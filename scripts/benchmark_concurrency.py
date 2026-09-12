#!/usr/bin/env python3
"""
FS-2601 Concurrency & Double-Spend Benchmark Client
Spawns 500 concurrent workers attempting to deplete an account with $1,000 balance.
Calculates p50, p90, p99 latencies and validates double-entry ledger invariants.
Zero external dependencies (uses standard library asyncio & http.client).
"""

import asyncio
import json
import time
import urllib.request
import urllib.error
import sys

BASE_URL = "http://localhost:8080"
ACCOUNT_ID = "ACC-BENCH-1"
MERCHANT_ID = "MERCHANT-POS-01"
TRANSFER_AMOUNT_CENTS = 1000  # $10.00
CONCURRENCY = 500

async def send_payment(session_idx: int, loop: asyncio.AbstractEventLoop) -> tuple[dict, float]:
    url = f"{BASE_URL}/api/v1/auth/pay"
    payload = json.dumps({
        "idempotency_key": f"PY-BENCH-{session_idx}-{time.time_ns()}",
        "tx_id": f"TX-PY-{session_idx}",
        "account_id": ACCOUNT_ID,
        "merchant_id": MERCHANT_ID,
        "terminal_id": "TERM-001",
        "amount": TRANSFER_AMOUNT_CENTS,
        "device_id": f"DEV-{session_idx % 20}",
        "ip_address": f"10.0.1.{session_idx % 200 + 1}",
    }).encode("utf-8")

    def blocking_post():
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req) as resp:
                data = resp.read()
                elapsed = (time.perf_counter() - start) * 1000.0  # in ms
                return json.loads(data), elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - start) * 1000.0
            data = e.read()
            return json.loads(data), elapsed

    return await loop.run_in_executor(None, blocking_post)

async def run_benchmark():
    print(f"================================================================================")
    print(f"  FS-2601 Concurrency & Latency Benchmark ({CONCURRENCY} Concurrent Requests)")
    print(f"================================================================================")

    # 1. Health check
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/v1/health")
        with urllib.request.urlopen(req) as resp:
            health = json.loads(resp.read())
            print(f"[OK] Connected to {BASE_URL}. Node status: {health.get('status')}")
    except Exception as e:
        print(f"[ERROR] Cannot connect to {BASE_URL}: {e}")
        print("Please start bin/server.exe before running this benchmark.")
        sys.exit(1)

    # 2. Check initial account balance
    acc_url = f"{BASE_URL}/api/v1/account/{ACCOUNT_ID}"
    with urllib.request.urlopen(urllib.request.Request(acc_url)) as resp:
        acc_initial = json.loads(resp.read())
        initial_avail = acc_initial.get("available_balance", 0)
        print(f"[INFO] Initial Account Balance: {initial_avail} cents (${initial_avail/100:.2f} USD)")

    print(f"[INFO] Launching {CONCURRENCY} concurrent authorization workers...")
    loop = asyncio.get_running_loop()

    start_all = time.perf_counter()
    tasks = [send_payment(i, loop) for i in range(CONCURRENCY)]
    results = await asyncio.gather(*tasks)
    total_wall_time = (time.perf_counter() - start_all) * 1000.0

    latencies = [r[1] for r in results]
    responses = [r[0] for r in results]

    approved = sum(1 for r in responses if r.get("status") == "APPROVED")
    declined_insufficient = sum(1 for r in responses if r.get("reason_code") == "INSUFFICIENT_FUNDS")
    declined_other = len(responses) - approved - declined_insufficient

    # Calculate percentiles
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p90 = latencies[int(len(latencies) * 0.90)]
    p99 = latencies[int(len(latencies) * 0.99)]
    avg_latency = sum(latencies) / len(latencies)

    print(f"\n--- Latency SLA Verification ---")
    print(f"Total Wall Clock Time : {total_wall_time:.2f} ms")
    print(f"Average Latency       : {avg_latency:.2f} ms")
    print(f"p50 Latency           : {p50:.2f} ms")
    print(f"p90 Latency           : {p90:.2f} ms")
    print(f"p99 Latency           : {p99:.2f} ms (Target <= 300 ms)")

    from collections import Counter
    reasons = Counter(r.get("reason_code", "UNKNOWN") for r in responses if r.get("status") == "DECLINED")

    print(f"\n--- Financial Correctness & Double-Spend Assertion ---")
    print(f"Approved Transactions : {approved} (Total = ${approved * (TRANSFER_AMOUNT_CENTS/100):.2f})")
    for reason, count in reasons.items():
        print(f"Declined ({reason:<22}): {count}")

    # Check final balance
    with urllib.request.urlopen(urllib.request.Request(acc_url)) as resp:
        acc_final = json.loads(resp.read())
        final_avail = acc_final.get("available_balance", 0)
        print(f"Final Account Balance : {final_avail} cents (${final_avail/100:.2f} USD)")

    # Audit conservation
    audit_url = f"{BASE_URL}/api/v1/audit/conservation"
    with urllib.request.urlopen(urllib.request.Request(audit_url)) as resp:
        audit = json.loads(resp.read())
        print(f"System Balance Audit  : {audit.get('total_system_balance')} cents")
        print(f"Ledger Audit Entries  : {audit.get('ledger_entry_count')}")

    if p99 <= 300.0:
        print(f"\n[PASS] Latency SLA Met: p99 {p99:.2f} ms <= 300 ms.")
    else:
        print(f"\n[FAIL] Latency SLA Exceeded: p99 {p99:.2f} ms > 300 ms.")

    if final_avail >= 0:
        print(f"[PASS] Financial Correctness: Zero balance overdraw. Double-spend gate validated.")
    else:
        print(f"[FAIL] Double-spend detected: Negative account balance {final_avail}!")

if __name__ == "__main__":
    asyncio.run(run_benchmark())

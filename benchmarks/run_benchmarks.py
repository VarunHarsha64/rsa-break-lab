#!/usr/bin/env python3
"""
run_benchmarks.py
------------------
Sweeps each attack over its relevant parameter (prime gap, d size,
etc.), records success/failure and timing, and writes:

    benchmarks/results/benchmark_results.csv
    benchmarks/results/benchmark_results.json
    benchmarks/results/*.png                  (if matplotlib is installed)
    docs/data/benchmark_results.json          (copy for the web demo)

This is the script that produces the numbers your report should cite.
Every row is also independently reproducible: it's just a call into
the same rsa_break_lab library the CLI and the web demo use.
"""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rsa_break_lab import rsa_core
from rsa_break_lab.attacks.fermat import fermat_factor
from rsa_break_lab.attacks.wiener import wiener_attack
from rsa_break_lab.attacks.hastad import hastad_broadcast
from rsa_break_lab.attacks.batch_gcd import batch_gcd

RESULTS_DIR = Path(__file__).parent / "results"
DOCS_DATA_DIR = Path(__file__).resolve().parents[1] / "docs" / "data"
PLOTS_DIR = RESULTS_DIR

rows = []  # each row: dict of benchmark + outcome, flat for CSV


def record(**kwargs):
    rows.append(kwargs)
    print(f"  {kwargs}")


def bench_fermat():
    print("\n[1/5] Fermat factorization vs. prime gap size")
    # For a 512-bit modulus (256-bit primes), Fermat's method is instant
    # whenever the gap between p and q is small relative to sqrt(n) --
    # the interesting transition for THIS key size only shows up once the
    # gap approaches roughly half the prime's bit length. These values
    # were picked empirically to span "instant" to "the 8M iteration cap".
    bits = 512
    for gap_bits in (100, 120, 128, 132, 135, 137, 139, 141, 143):
        for trial in range(5):
            kp = rsa_core.generate_close_primes_keypair(bits=bits, gap_bits=gap_bits)
            t0 = time.perf_counter()
            factors, iterations = fermat_factor(kp.n, max_iterations=8_000_000)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            record(
                attack="fermat", parameter="gap_bits", value=gap_bits, trial=trial,
                n_bits=bits, success=factors is not None,
                iterations=iterations, duration_ms=round(elapsed_ms, 4),
            )


def bench_wiener():
    print("\n[2/5] Wiener's attack vs. private exponent size")
    bits = 1024
    # Wiener's bound: d < (1/3) n^0.25 -> for 1024-bit n that's ~254 bits.
    # Sweep straddles that boundary to show the sharp cutoff empirically.
    for d_bits in (150, 200, 230, 250, 254, 256, 260, 270, 300):
        for trial in range(5):
            kp = rsa_core.generate_small_d_keypair(bits=bits, d_bits=d_bits)
            t0 = time.perf_counter()
            d, factors, convergents = wiener_attack(kp.e, kp.n)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            record(
                attack="wiener", parameter="d_bits", value=d_bits, trial=trial,
                n_bits=bits, success=(d == kp.d),
                convergents_tried=convergents, duration_ms=round(elapsed_ms, 4),
            )


def bench_hastad():
    print("\n[3/5] Hastad broadcast vs. number of intercepted ciphertexts")
    bits = 512
    e = 3
    # Message must be close in size to the modulus so m**e genuinely wraps
    # mod n_i -- otherwise a single ciphertext's plain e-th root would
    # already reveal m, and the CRT combination wouldn't be proving anything.
    import random
    message = random.getrandbits(bits - 16) | (1 << (bits - 17))
    for k in (1, 2, 3, 4):  # need >= e to succeed
        for trial in range(5):
            keypairs, cts = rsa_core.generate_broadcast_instance(message=message, k=k, bits=bits, e=e)
            pairs = [(kp.n, c) for kp, c in zip(keypairs, cts)]
            # An attacker with MORE than e intercepted ciphertexts just uses
            # any e of them; hastad_broadcast infers e from len(pairs), so
            # we must not hand it extra ciphertexts or it'll assume the
            # wrong exponent. With fewer than e, the attack is run as-is
            # and is expected to fail -- that's the point of this sweep.
            attack_pairs = pairs[:e] if len(pairs) >= e else pairs
            t0 = time.perf_counter()
            recovered, details = hastad_broadcast(attack_pairs)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            record(
                attack="hastad", parameter="num_ciphertexts", value=k, trial=trial,
                n_bits=bits, success=(recovered == message),
                duration_ms=round(elapsed_ms, 4),
            )


def bench_common_modulus():
    print("\n[4/5] Common modulus attack vs. modulus size")
    from rsa_break_lab.attacks.common_modulus import common_modulus_attack
    message = 20251112
    for bits in (256, 512, 1024, 2048):
        for trial in range(5):
            n, (e1, c1), (e2, c2) = rsa_core.generate_common_modulus_instance(message=message, bits=bits)
            t0 = time.perf_counter()
            m = common_modulus_attack(n, e1, c1, e2, c2)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            record(
                attack="common_modulus", parameter="n_bits", value=bits, trial=trial,
                n_bits=bits, success=(m == message),
                duration_ms=round(elapsed_ms, 4),
            )


def bench_batch_gcd():
    print("\n[5/5] Batch GCD vs. pool size")
    bits = 256
    for pool_size in (5, 10, 20, 40, 80):
        for trial in range(3):
            pool = rsa_core.generate_shared_prime_pool(
                count=pool_size, bits=bits, num_colliding_pairs=1
            )
            moduli = [kp.n for kp in pool]
            t0 = time.perf_counter()
            compromised, comparisons = batch_gcd(moduli)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            record(
                attack="batch_gcd", parameter="pool_size", value=pool_size, trial=trial,
                n_bits=bits, success=(len(compromised) == 2),
                comparisons=comparisons, duration_ms=round(elapsed_ms, 4),
            )


def write_results():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    json_path = RESULTS_DIR / "benchmark_results.json"
    json_path.write_text(json.dumps(rows, indent=2))
    (DOCS_DATA_DIR / "benchmark_results.json").write_text(json.dumps(rows, indent=2))

    fieldnames = sorted({k for row in rows for k in row.keys()})
    csv_path = RESULTS_DIR / "benchmark_results.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Copy the CSV alongside the JSON so the GitHub Pages demo can offer a
    # direct "download the data" link (Pages only serves docs/, not benchmarks/).
    (DOCS_DATA_DIR / "benchmark_results.csv").write_text(csv_path.read_text())

    print(
        f"\nWrote {len(rows)} benchmark rows to:\n  {json_path}\n  {csv_path}\n"
        f"  {DOCS_DATA_DIR / 'benchmark_results.json'} (demo copy)\n"
        f"  {DOCS_DATA_DIR / 'benchmark_results.csv'} (demo copy)"
    )


def write_plots():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed -- skipping charts (CSV/JSON still written).")
        return

    import statistics as stats

    def grouped(attack, parameter, value_key="value", metric_key="duration_ms", only_success=True):
        subset = [r for r in rows if r["attack"] == attack and r["parameter"] == parameter]
        if only_success:
            subset = [r for r in subset if r["success"]]
        buckets = {}
        for r in subset:
            buckets.setdefault(r[value_key], []).append(r[metric_key])
        xs = sorted(buckets)
        ys = [stats.mean(buckets[x]) for x in xs]
        return xs, ys

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Fermat: time vs gap size (log scale y, since cost grows exponentially
    # with gap). Include capped/failed runs too -- the time spent hitting the
    # iteration cap IS the data point that shows the attack becoming impractical.
    xs, ys = grouped("fermat", "gap_bits", only_success=False)
    plt.figure(figsize=(6, 4))
    plt.plot(xs, ys, marker="o")
    plt.yscale("log")
    plt.xlabel("prime gap size (bits)")
    plt.ylabel("time to factor (ms, log scale)")
    plt.title("Fermat factorization cost vs. |p - q|")
    plt.grid(True, which="both", alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "fermat_time_vs_gap.png", dpi=150)
    plt.close()

    # 2. Wiener: success rate vs d_bits
    subset = [r for r in rows if r["attack"] == "wiener"]
    buckets = {}
    for r in subset:
        buckets.setdefault(r["value"], []).append(r["success"])
    xs = sorted(buckets)
    ys = [100.0 * sum(buckets[x]) / len(buckets[x]) for x in xs]
    plt.figure(figsize=(7, 4))
    bar_colors = ["#4C72B0" if x <= 254 else "#999999" for x in xs]
    plt.bar([str(x) for x in xs], ys, color=bar_colors)
    plt.axhline(100, color="gray", linestyle="--", linewidth=0.8)
    plt.xlabel("private exponent size d (bits), n = 1024 bits")
    plt.ylabel("attack success rate (%)")
    plt.title("Wiener's attack success rate vs. |d|\n(theoretical bound ~254 bits for 1024-bit n)")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "wiener_success_vs_dbits.png", dpi=150)
    plt.close()

    # 3. Batch GCD: comparisons vs pool size (shows O(k^2) growth)
    xs, ys = grouped("batch_gcd", "pool_size", metric_key="comparisons")
    plt.figure(figsize=(6, 4))
    plt.plot(xs, ys, marker="o", color="#C44E52")
    plt.xlabel("pool size (number of moduli)")
    plt.ylabel("pairwise GCD comparisons")
    plt.title("Batch GCD cost scaling (O(k^2) pairwise version)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "batch_gcd_scaling.png", dpi=150)
    plt.close()

    print(f"Wrote charts to {PLOTS_DIR}/*.png")


def main():
    print("Running RSA Break Lab benchmark suite...")
    bench_fermat()
    bench_wiener()
    bench_hastad()
    bench_common_modulus()
    bench_batch_gcd()
    write_results()
    write_plots()
    print("\nBenchmark run complete.")


if __name__ == "__main__":
    main()

"""
Command-line interface.

    python -m rsa_break_lab generate close_primes --bits 512 -o key.json
    python -m rsa_break_lab break key.json

`generate` plants one of the five weaknesses this project attacks.
`break` loads a JSON description of a target and auto-detects + runs
the appropriate attack(s), logging every attempt (even the ones that
fail) to logs/attack_log.jsonl for the statistics/report pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import random

from . import rsa_core
from .attacks import (
    fermat_factor,
    wiener_attack,
    hastad_broadcast,
    common_modulus_attack,
    batch_gcd,
)
from .logging_utils import AttackLogger

DEMO_MESSAGE = 42  # a small illustrative "secret" plaintext (fine for common_modulus)


def _big_message(bits: int) -> int:
    """A message close in size to the modulus -- needed for the broadcast
    demo so m**e genuinely wraps mod n_i instead of each ciphertext just
    being an unreduced m**e (which would make a single plain e-th root
    enough, defeating the point of demonstrating the CRT combination)."""
    return random.getrandbits(bits - 16) | (1 << (bits - 17))


# --------------------------------------------------------------------------
# generate
# --------------------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> None:
    kind = args.kind
    out = Path(args.output)

    if kind == "close_primes":
        kp = rsa_core.generate_close_primes_keypair(bits=args.bits, gap_bits=args.gap_bits)
        data = {
            "weakness": "close_primes",
            "n": kp.n, "e": kp.e,
            "_ground_truth": {"d": kp.d, "p": kp.p, "q": kp.q, "gap_bits": args.gap_bits},
        }

    elif kind == "small_d":
        kp = rsa_core.generate_small_d_keypair(bits=args.bits, d_bits=args.d_bits)
        data = {
            "weakness": "small_d",
            "n": kp.n, "e": kp.e,
            "_ground_truth": {"d": kp.d, "p": kp.p, "q": kp.q, "d_bits": args.d_bits},
        }

    elif kind == "broadcast":
        message = _big_message(args.bits)
        keypairs, cts = rsa_core.generate_broadcast_instance(
            message=message, k=args.k, bits=args.bits, e=args.e
        )
        data = {
            "weakness": "broadcast",
            "e": args.e,
            "targets": [{"n": kp.n, "c": c} for kp, c in zip(keypairs, cts)],
            "_ground_truth": {"message": message},
        }

    elif kind == "common_modulus":
        n, (e1, c1), (e2, c2) = rsa_core.generate_common_modulus_instance(
            message=DEMO_MESSAGE, bits=args.bits
        )
        data = {
            "weakness": "common_modulus",
            "n": n, "e1": e1, "c1": c1, "e2": e2, "c2": c2,
            "_ground_truth": {"message": DEMO_MESSAGE},
        }

    elif kind == "shared_prime":
        pool = rsa_core.generate_shared_prime_pool(
            count=args.count, bits=args.bits, num_colliding_pairs=args.colliding_pairs
        )
        data = {
            "weakness": "shared_prime",
            "moduli": [kp.n for kp in pool],
            "_ground_truth": {"primes": [[kp.p, kp.q] for kp in pool]},
        }

    else:
        raise ValueError(f"unknown weakness kind: {kind}")

    out.write_text(json.dumps(data, indent=2))
    print(f"wrote {kind} target -> {out}")


# --------------------------------------------------------------------------
# break
# --------------------------------------------------------------------------

def cmd_break(args: argparse.Namespace) -> None:
    data = json.loads(Path(args.target).read_text())
    logger = AttackLogger(log_path=args.log)
    weakness = data.get("weakness", "unknown")
    print(f"Loaded target (declared weakness: {weakness}). Running auto-detection...\n")

    solved = False

    # --- try Fermat (cheap first guess, works whenever p, q are close) ---
    if "n" in data and "e" in data:
        n = data["n"]
        with logger.timed("fermat", n_bits=n.bit_length()) as ctx:
            factors, iters = fermat_factor(n, max_iterations=args.fermat_iterations)
            ctx.details["iterations"] = iters
            if factors:
                p, q = factors
                ctx.success = True
                print(f"  -> FACTORED via Fermat: p={p}\n                  q={q}")
                solved = True

    # --- try Wiener (cheap, works whenever d is small) ---
    if not solved and "n" in data and "e" in data:
        n, e = data["n"], data["e"]
        with logger.timed("wiener", n_bits=n.bit_length()) as ctx:
            d, factors, tried = wiener_attack(e, n)
            ctx.details["convergents_tried"] = tried
            if d is not None:
                ctx.success = True
                print(f"  -> RECOVERED private exponent via Wiener: d={d}")
                solved = True

    # --- common modulus ---
    if not solved and all(k in data for k in ("n", "e1", "c1", "e2", "c2")):
        with logger.timed("common_modulus", n_bits=data["n"].bit_length()) as ctx:
            m = common_modulus_attack(data["n"], data["e1"], data["c1"], data["e2"], data["c2"])
            ctx.success = True
            ctx.details["recovered_message"] = m
            print(f"  -> RECOVERED message via common modulus attack: m={m}")
            solved = True

    # --- broadcast (Hastad) ---
    if not solved and "targets" in data:
        pairs = [(t["n"], t["c"]) for t in data["targets"]]
        with logger.timed("hastad_broadcast", num_targets=len(pairs)) as ctx:
            m, details = hastad_broadcast(pairs)
            ctx.details.update(details)
            if m is not None:
                ctx.success = True
                print(f"  -> RECOVERED message via Hastad broadcast attack: m={m}")
                solved = True

    # --- batch GCD (needs a pool of moduli, not a single target) ---
    if not solved and "moduli" in data:
        moduli = data["moduli"]
        with logger.timed("batch_gcd", pool_size=len(moduli)) as ctx:
            compromised, comparisons = batch_gcd(moduli)
            ctx.details["comparisons"] = comparisons
            ctx.details["num_compromised"] = len(compromised)
            if compromised:
                ctx.success = True
                solved = True
                for idx, (shared_p, cofactor) in compromised.items():
                    print(f"  -> key #{idx} compromised: shared prime found, n = p * q with p={shared_p}")

    if not solved:
        print("\nNo attack in this toolkit succeeded against this target.")
        sys.exit(1)
    else:
        print(f"\nDone. Full structured log written to {args.log}")


# --------------------------------------------------------------------------
# argparse wiring
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rsa_break_lab")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="generate a deliberately weak RSA target")
    gen.add_argument("kind", choices=[
        "close_primes", "small_d", "broadcast", "common_modulus", "shared_prime",
    ])
    gen.add_argument("--bits", type=int, default=512)
    gen.add_argument("--gap-bits", type=int, default=8, help="for close_primes")
    gen.add_argument("--d-bits", type=int, default=60, help="for small_d")
    gen.add_argument("--k", type=int, default=3, help="number of broadcast targets")
    gen.add_argument("--e", type=int, default=3, help="broadcast exponent")
    gen.add_argument("--count", type=int, default=10, help="pool size for shared_prime")
    gen.add_argument("--colliding-pairs", type=int, default=1)
    gen.add_argument("-o", "--output", default="target.json")
    gen.set_defaults(func=cmd_generate)

    brk = sub.add_parser("break", help="auto-detect and break a target")
    brk.add_argument("target")
    brk.add_argument("--log", default="logs/attack_log.jsonl")
    brk.add_argument("--fermat-iterations", type=int, default=2_000_000)
    brk.set_defaults(func=cmd_break)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

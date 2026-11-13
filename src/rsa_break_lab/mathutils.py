"""
mathutils.py
------------
Small, dependency-free number theory toolkit used across the whole
project (key generation AND attacks). Everything here is implemented
from scratch on purpose -- part of the point of an "advanced
cryptography" project is showing you understand what a library like
`cryptography` or `sympy` is doing under the hood, not importing it.

Only the Python standard library is used (random, math), so this file
also runs unmodified inside Pyodide for the browser demo.
"""

from __future__ import annotations

import math
import random
from typing import Optional, Tuple

# --------------------------------------------------------------------------
# Primality testing
# --------------------------------------------------------------------------

_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test.

    `rounds` controls the false-positive probability (<= 4^-rounds).
    40 rounds gives a probability of error far below 2^-80, which is
    the standard used by production crypto libraries for key generation.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # Write n-1 as 2^r * d with d odd.
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime with exactly `bits` bits (top bit set)."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_prime_near(center: int, max_offset_bits: int) -> int:
    """Generate a prime within +/- 2^max_offset_bits of `center`.

    Used to build Fermat-vulnerable RSA moduli, where p and q are chosen
    too close together.
    """
    max_offset = 1 << max_offset_bits
    while True:
        offset = random.randrange(1, max_offset)
        sign = random.choice((-1, 1))
        candidate = center + sign * offset
        candidate |= 1  # force odd
        if candidate > 2 and is_probable_prime(candidate):
            return candidate


# --------------------------------------------------------------------------
# Modular arithmetic
# --------------------------------------------------------------------------

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (g, x, y) s.t. a*x + b*y = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m. Raises ValueError if it doesn't exist."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"modular inverse does not exist for {a} mod {m}")
    return x % m


def integer_nth_root(x: int, n: int) -> Tuple[int, bool]:
    """Floor(x ** (1/n)) computed exactly on integers, plus an exactness flag.

    Uses Newton's method, which converges fast and exactly for big ints.
    """
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0, True
    if n == 1:
        return x, True

    # Initial guess via bit length (cheap and close enough for Newton).
    guess = 1 << ((x.bit_length() // n) + 1)
    while True:
        delta = (((n - 1) * guess + x // pow(guess, n - 1)) // n)
        if delta >= guess:
            break
        guess = delta
    # `guess` is now floor(root) or very close; nudge to be exact.
    while pow(guess + 1, n) <= x:
        guess += 1
    while pow(guess, n) > x:
        guess -= 1
    return guess, pow(guess, n) == x


def isqrt(n: int) -> int:
    """Thin wrapper kept for readability/consistency across attack modules."""
    return math.isqrt(n)

"""
Wiener's attack (1990).

If the private exponent d < (1/3) * n^(1/4), d/k is a convergent of the
continued fraction expansion of e/n, for some small integer k. We walk
the continued-fraction convergents of e/n and test each as a candidate
(k, d); the correct one lets us reconstruct phi(n) and then factor n
via the quadratic x^2 - (n - phi + 1)x + n = 0.
"""

from __future__ import annotations

from typing import Iterator, Optional, Tuple

from ..mathutils import isqrt


def _continued_fraction(num: int, den: int) -> Iterator[int]:
    while den:
        a = num // den
        yield a
        num, den = den, num - a * den


def _convergents(cf_terms) -> Iterator[Tuple[int, int]]:
    """Yield (h_i, k_i) convergents h_i/k_i from continued fraction terms."""
    h_prev2, h_prev1 = 0, 1
    k_prev2, k_prev1 = 1, 0
    for a in cf_terms:
        h = a * h_prev1 + h_prev2
        k = a * k_prev1 + k_prev2
        yield h, k
        h_prev2, h_prev1 = h_prev1, h
        k_prev2, k_prev1 = k_prev1, k


def wiener_attack(e: int, n: int) -> Tuple[Optional[int], Optional[Tuple[int, int]], int]:
    """Attempt to recover d (and the factorization of n) from (e, n).

    Returns (d, (p, q), convergents_tried). (None, None, count) on failure.
    """
    count = 0
    for k, d in _convergents(_continued_fraction(e, n)):
        count += 1
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (n - phi + 1) x + n = 0 for integer roots p, q.
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sqrt_disc = isqrt(disc)
        if sqrt_disc * sqrt_disc != disc:
            continue
        if (b - sqrt_disc) % 2 != 0:
            continue
        p = (b - sqrt_disc) // 2
        q = (b + sqrt_disc) // 2
        if p > 1 and q > 1 and p * q == n:
            return d, (p, q), count

    return None, None, count

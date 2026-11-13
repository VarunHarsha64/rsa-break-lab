"""
Fermat's factorization method.

Idea: if n = p*q with p and q close together, then n can be written as
a difference of squares n = a^2 - b^2 = (a-b)(a+b), with a = (p+q)/2
close to sqrt(n). We search a = ceil(sqrt(n)), ceil(sqrt(n))+1, ...
until a^2 - n is itself a perfect square b^2. Then p = a-b, q = a+b.

Cost: roughly proportional to |p - q| / 2, so this is only practical
when the primes are abnormally close -- which is exactly the weakness
`generate_close_primes_keypair` plants.
"""

from __future__ import annotations

from typing import Optional, Tuple

from ..mathutils import isqrt


def fermat_factor(n: int, max_iterations: int = 2_000_000) -> Tuple[Optional[Tuple[int, int]], int]:
    """Try to factor n via Fermat's method.

    Returns ((p, q), iterations_used). (None, iterations_used) on failure.
    """
    if n % 2 == 0:
        return (2, n // 2), 0

    a = isqrt(n)
    if a * a < n:
        a += 1

    for i in range(max_iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            return (p, q), i + 1
        a += 1

    return None, max_iterations

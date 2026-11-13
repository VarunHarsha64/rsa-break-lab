"""
Batch GCD.

If two "independent" RSA moduli n_i = p_i * q_i and n_j = p_j * q_j
happen to share a prime factor (p_i == p_j, say, because both devices
seeded their RNG with low entropy at boot), then gcd(n_i, n_j) reveals
that shared prime immediately -- no factoring algorithm needed at all.
This is a real, historically-documented failure mode: see Lenstra et
al. and Heninger et al.'s 2012 Internet-wide scans ("Mining Your Ps
and Qs", "Ron was wrong, Whit is right").

This module implements the simple O(k^2) pairwise version, which is
plenty fast for a classroom-sized key pool, and a note in the README
describes the O(k log k) product-tree version real scanners use.
"""

from __future__ import annotations

from math import gcd
from typing import Dict, List, Tuple


def batch_gcd(moduli: List[int]) -> Tuple[Dict[int, Tuple[int, int]], int]:
    """Pairwise-GCD every modulus in `moduli` against every other one.

    Returns (compromised, comparisons_made) where `compromised` maps
    index -> (shared_prime, cofactor) for every modulus that was broken.
    """
    compromised: Dict[int, Tuple[int, int]] = {}
    comparisons = 0
    k = len(moduli)

    for i in range(k):
        if i in compromised:
            continue
        for j in range(i + 1, k):
            comparisons += 1
            g = gcd(moduli[i], moduli[j])
            if g != 1 and g != moduli[i] and g != moduli[j]:
                compromised[i] = (g, moduli[i] // g)
                compromised[j] = (g, moduli[j] // g)

    return compromised, comparisons

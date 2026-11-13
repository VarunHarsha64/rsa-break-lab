"""
Hastad's broadcast attack (1988).

If the same message m is encrypted with the same small exponent e
under e (or more) pairwise-coprime moduli n_1..n_e, an eavesdropper
who intercepts all e ciphertexts can recover m without factoring
anything:

  1. Use the Chinese Remainder Theorem to combine the e congruences
     c_i = m^e mod n_i into a single congruence  x = m^e  mod N,
     where N = n_1 * n_2 * ... * n_e.
  2. Because m < every n_i, we have m^e < N, so x (CRT's output,
     which is already the unique value in [0, N)) is *exactly* m^e,
     not just congruent to it.
  3. Take the ordinary integer e-th root of x to recover m.

This is why real systems use OAEP padding: padding makes the e
plaintexts under different moduli different, breaking step 2.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from ..mathutils import egcd, integer_nth_root


def _crt(remainders: Sequence[int], moduli: Sequence[int]) -> int:
    """Combine x = r_i (mod m_i) for pairwise-coprime m_i into one x mod N."""
    x, N = remainders[0], moduli[0]
    for r, m in zip(remainders[1:], moduli[1:]):
        g, p, q = egcd(N, m)
        if g != 1:
            raise ValueError("moduli are not pairwise coprime; CRT does not apply")
        # Combine (x mod N) and (r mod m) into one residue mod N*m.
        x = (x * m * q + r * N * p) % (N * m)
        N *= m
    return x % N


def hastad_broadcast(pairs: List[Tuple[int, int]]) -> Tuple[Optional[int], dict]:
    """pairs: list of (n_i, c_i) using the SAME public exponent e = len(pairs).

    Returns (recovered_message_or_None, details_dict).
    """
    e = len(pairs)
    moduli = [n for n, _ in pairs]
    remainders = [c for _, c in pairs]

    details = {"num_ciphertexts": e}

    combined = _crt(remainders, moduli)
    details["combined_bit_length"] = combined.bit_length()

    m, exact = integer_nth_root(combined, e)
    details["exact_root"] = exact
    if exact:
        return m, details
    return None, details

"""
Common modulus attack.

If two users share the same modulus n but have coprime public
exponents e1, e2, and the SAME message m was encrypted for both
(c1 = m^e1 mod n, c2 = m^e2 mod n), an attacker who knows n, e1, e2,
c1, c2 recovers m without ever factoring n or learning either
private key.

Bezout's identity gives integers a, b with a*e1 + b*e2 = 1 (since
gcd(e1, e2) = 1). Then:

    c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1 + b*e2) = m^1 = m  (mod n)

One of a, b will typically be negative, which we handle via modular
inverse of the corresponding ciphertext.
"""

from __future__ import annotations

from typing import Tuple

from ..mathutils import egcd, modinv


def common_modulus_attack(n: int, e1: int, c1: int, e2: int, c2: int) -> int:
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 and e2 must be coprime for this attack to work")

    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b

    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m

"""
rsa_core.py
-----------
Minimal textbook RSA, plus five deliberately-weakened key generators,
one per attack this project implements:

    close_primes     -> Fermat factorization
    small_private_d  -> Wiener's attack
    broadcast        -> Hastad's broadcast attack
    common_modulus   -> common modulus attack
    shared_prime     -> batch GCD

None of this is meant to be used for real encryption. It exists to
produce realistic-looking "vulnerable key" artifacts to attack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .mathutils import generate_prime, generate_prime_near, modinv, egcd


@dataclass
class KeyPair:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public(self) -> Tuple[int, int]:
        return (self.n, self.e)


def encrypt(message: int, n: int, e: int) -> int:
    if message >= n:
        raise ValueError("message must be smaller than the modulus")
    return pow(message, e, n)


def decrypt(ciphertext: int, d: int, n: int) -> int:
    return pow(ciphertext, d, n)


# --------------------------------------------------------------------------
# Secure baseline generator (for comparison / sanity checks)
# --------------------------------------------------------------------------

def generate_keypair(bits: int = 1024, e: int = 65537) -> KeyPair:
    """A normal, non-vulnerable RSA keypair: p and q are independent
    random primes of bits/2 length each, chosen far apart."""
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            d = modinv(e, phi)
        except ValueError:
            continue
        return KeyPair(n=n, e=e, d=d, p=p, q=q)


# --------------------------------------------------------------------------
# Weak generator #1: close primes -> Fermat factorization
# --------------------------------------------------------------------------

def generate_close_primes_keypair(bits: int = 512, gap_bits: int = 8, e: int = 65537) -> KeyPair:
    """p and q are within ~2^gap_bits of each other instead of being
    independently random -- textbook Fermat-factorization bait."""
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime_near(p, gap_bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return KeyPair(n=n, e=e, d=d, p=p, q=q)


# --------------------------------------------------------------------------
# Weak generator #2: small private exponent -> Wiener's attack
# --------------------------------------------------------------------------

def generate_small_d_keypair(bits: int = 1024, d_bits: int = 60) -> KeyPair:
    """Pick a *small* private exponent d first, then derive e from it.
    Wiener's theorem: this is breakable whenever d < (1/3) * n^0.25.
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        d = generate_prime(d_bits)  # doesn't need to be prime, but keeps gcd(d,phi) issues rare
        g, _, _ = egcd(d, phi)
        if g != 1:
            continue
        e = modinv(d, phi)
        if e.bit_length() < bits - 2:
            # e came out too small to be realistic/interesting; retry
            continue
        return KeyPair(n=n, e=e, d=d, p=p, q=q)


# --------------------------------------------------------------------------
# Weak generator #3: same small e, many moduli -> Hastad broadcast
# --------------------------------------------------------------------------

def generate_broadcast_instance(message: int, k: int = 3, bits: int = 512, e: int = 3):
    """Encrypt the SAME message under k different moduli with the SAME
    small public exponent e. Returns (keypairs, ciphertexts).
    """
    keypairs: List[KeyPair] = []
    ciphertexts: List[int] = []
    while len(keypairs) < k:
        kp = generate_keypair(bits=bits, e=e)
        if message >= kp.n:
            continue
        # Hastad's attack requires the e-th power (not just the message)
        # to be smaller than the product of moduli, which holds here as
        # long as message < every n_i -- true by construction above.
        keypairs.append(kp)
        ciphertexts.append(encrypt(message, kp.n, kp.e))
    return keypairs, ciphertexts


# --------------------------------------------------------------------------
# Weak generator #4: same modulus, two exponents -> common modulus attack
# --------------------------------------------------------------------------

def generate_common_modulus_instance(message: int, bits: int = 1024):
    """Two different "users" are (mis-)configured to share the same
    modulus n but use different public exponents e1 != e2.
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if message >= n:
            continue
        e1 = 65537
        g1, _, _ = egcd(e1, phi)
        if g1 != 1:
            continue
        # pick e2 coprime to phi AND to e1 (required by the attack)
        e2 = 17
        while True:
            g2, _, _ = egcd(e2, phi)
            g3, _, _ = egcd(e1, e2)
            if g2 == 1 and g3 == 1:
                break
            e2 += 2
        c1 = encrypt(message, n, e1)
        c2 = encrypt(message, n, e2)
        return n, (e1, c1), (e2, c2)


# --------------------------------------------------------------------------
# Weak generator #5: shared prime across independent keys -> batch GCD
# --------------------------------------------------------------------------

def generate_shared_prime_pool(count: int = 10, bits: int = 256, e: int = 65537,
                                 num_colliding_pairs: int = 1) -> List[KeyPair]:
    """Generate `count` independent-looking keypairs, but secretly make
    `num_colliding_pairs` of them share one prime factor -- simulating
    many devices/services reusing a weak or low-entropy RNG at
    key-generation time (this really happened; see the 2012 Lenstra/
    Heninger "Mining Your Ps and Qs" studies referenced in the README).
    """
    half = bits // 2
    keypairs: List[KeyPair] = []

    colliding_slots = num_colliding_pairs * 2
    shared_primes = [generate_prime(half) for _ in range(num_colliding_pairs)]

    for i in range(count):
        if i < colliding_slots:
            shared_p = shared_primes[i // 2]
            q = generate_prime(half)
            while q == shared_p:
                q = generate_prime(half)
            p = shared_p
        else:
            p = generate_prime(half)
            q = generate_prime(half)
            while q == p:
                q = generate_prime(half)

        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            d = modinv(e, phi)
        except ValueError:
            continue
        keypairs.append(KeyPair(n=n, e=e, d=d, p=p, q=q))

    return keypairs

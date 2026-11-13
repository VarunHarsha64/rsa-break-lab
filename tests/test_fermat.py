import unittest

from rsa_break_lab.rsa_core import generate_close_primes_keypair, generate_keypair
from rsa_break_lab.attacks.fermat import fermat_factor


class TestFermat(unittest.TestCase):
    def test_breaks_close_primes(self):
        kp = generate_close_primes_keypair(bits=256, gap_bits=8)
        factors, iterations = fermat_factor(kp.n, max_iterations=2_000_000)
        self.assertIsNotNone(factors)
        p, q = factors
        self.assertEqual(p * q, kp.n)
        self.assertEqual({p, q}, {kp.p, kp.q})
        self.assertLess(iterations, 2_000_000)

    def test_fails_on_well_separated_primes(self):
        kp = generate_keypair(bits=256)
        factors, iterations = fermat_factor(kp.n, max_iterations=5000)
        self.assertIsNone(factors)


if __name__ == "__main__":
    unittest.main()

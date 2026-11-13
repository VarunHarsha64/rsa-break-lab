import unittest

from rsa_break_lab.rsa_core import generate_small_d_keypair, generate_keypair
from rsa_break_lab.attacks.wiener import wiener_attack


class TestWiener(unittest.TestCase):
    def test_breaks_small_d(self):
        kp = generate_small_d_keypair(bits=1024, d_bits=60)
        d, factors, tried = wiener_attack(kp.e, kp.n)
        self.assertEqual(d, kp.d)
        self.assertIsNotNone(factors)
        p, q = factors
        self.assertEqual({p, q}, {kp.p, kp.q})

    def test_fails_on_normal_d(self):
        kp = generate_keypair(bits=512)  # d is a full-size, normal exponent here
        d, factors, tried = wiener_attack(kp.e, kp.n)
        self.assertIsNone(d)


if __name__ == "__main__":
    unittest.main()

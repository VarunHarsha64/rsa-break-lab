import unittest

from rsa_break_lab.mathutils import (
    is_probable_prime, generate_prime, egcd, modinv, integer_nth_root,
)


class TestMathUtils(unittest.TestCase):
    def test_known_primes(self):
        for p in (2, 3, 5, 7, 97, 7919, 1_000_003):
            self.assertTrue(is_probable_prime(p))

    def test_known_composites(self):
        for c in (1, 4, 6, 9, 100, 1_000_002):
            self.assertFalse(is_probable_prime(c))

    def test_generate_prime_has_correct_bit_length(self):
        for bits in (16, 64, 128):
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_probable_prime(p))

    def test_egcd_bezout_identity(self):
        a, b = 240, 46
        g, x, y = egcd(a, b)
        self.assertEqual(g, 2)
        self.assertEqual(a * x + b * y, g)

    def test_modinv_correct(self):
        a, m = 17, 3120
        inv = modinv(a, m)
        self.assertEqual((a * inv) % m, 1)

    def test_integer_nth_root_exact(self):
        root, exact = integer_nth_root(2 ** 30, 3)
        self.assertTrue(exact)
        self.assertEqual(root, 2 ** 10)

    def test_integer_nth_root_inexact(self):
        root, exact = integer_nth_root(1001, 3)
        self.assertFalse(exact)
        self.assertEqual(root, 10)  # floor(1001 ** (1/3)) == 10 (10^3=1000 < 1001 < 1331=11^3)


if __name__ == "__main__":
    unittest.main()

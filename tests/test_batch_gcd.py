import unittest

from rsa_break_lab.rsa_core import generate_shared_prime_pool
from rsa_break_lab.attacks.batch_gcd import batch_gcd


class TestBatchGcd(unittest.TestCase):
    def test_finds_shared_prime(self):
        pool = generate_shared_prime_pool(count=12, bits=256, num_colliding_pairs=1)
        moduli = [kp.n for kp in pool]
        compromised, comparisons = batch_gcd(moduli)

        self.assertEqual(len(compromised), 2)  # exactly the colliding pair
        idxs = list(compromised.keys())
        shared_p_0, cofactor_0 = compromised[idxs[0]]
        shared_p_1, cofactor_1 = compromised[idxs[1]]
        self.assertEqual(shared_p_0, shared_p_1)
        # reconstructed factorization must multiply back to n
        self.assertEqual(shared_p_0 * cofactor_0, moduli[idxs[0]])
        self.assertEqual(shared_p_1 * cofactor_1, moduli[idxs[1]])

    def test_no_false_positives_without_collisions(self):
        pool = generate_shared_prime_pool(count=8, bits=256, num_colliding_pairs=0)
        moduli = [kp.n for kp in pool]
        compromised, comparisons = batch_gcd(moduli)
        self.assertEqual(len(compromised), 0)


if __name__ == "__main__":
    unittest.main()

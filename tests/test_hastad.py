import random
import unittest

from rsa_break_lab.rsa_core import generate_broadcast_instance
from rsa_break_lab.attacks.hastad import hastad_broadcast


def _big_message(bits: int) -> int:
    """A message close in size to the modulus, so m**e genuinely wraps
    around mod n_i -- otherwise a single ciphertext's plain e-th root
    would already reveal m and the broadcast/CRT step proves nothing."""
    return random.getrandbits(bits - 16) | (1 << (bits - 17))


class TestHastad(unittest.TestCase):
    def test_recovers_broadcast_message(self):
        bits = 256
        message = _big_message(bits)
        keypairs, cts = generate_broadcast_instance(message=message, k=3, bits=bits, e=3)
        pairs = [(kp.n, c) for kp, c in zip(keypairs, cts)]

        # Sanity check this test is actually exercising CRT: at least one
        # ciphertext must be a genuine reduction (c_i != message**e).
        self.assertTrue(any(c != message ** 3 for c in cts))

        recovered, details = hastad_broadcast(pairs)
        self.assertEqual(recovered, message)
        self.assertTrue(details["exact_root"])

    def test_fails_with_too_few_ciphertexts(self):
        bits = 256
        message = _big_message(bits)
        keypairs, cts = generate_broadcast_instance(message=message, k=3, bits=bits, e=3)
        pairs = [(kp.n, c) for kp, c in zip(keypairs, cts)][:2]  # only 2 of 3 needed for e=3
        recovered, details = hastad_broadcast(pairs)
        self.assertIsNone(recovered)


if __name__ == "__main__":
    unittest.main()

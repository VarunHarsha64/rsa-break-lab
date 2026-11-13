import unittest

from rsa_break_lab.rsa_core import generate_common_modulus_instance
from rsa_break_lab.attacks.common_modulus import common_modulus_attack


class TestCommonModulus(unittest.TestCase):
    def test_recovers_message(self):
        message = 987654321
        n, (e1, c1), (e2, c2) = generate_common_modulus_instance(message=message, bits=512)
        recovered = common_modulus_attack(n, e1, c1, e2, c2)
        self.assertEqual(recovered, message)


if __name__ == "__main__":
    unittest.main()

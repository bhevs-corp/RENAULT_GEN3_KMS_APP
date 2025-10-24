import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest
import time
from api.AES256 import TokenManager

class TestTokenManager(unittest.TestCase):
    def setUp(self):
        self.token_mgr = TokenManager()

    def test_encrypt_decrypt(self):
        payload = {"exp": time.time() + 3600, "user": "testuser"}
        token = self.token_mgr.encrypt(payload)
        decoded = self.token_mgr.decrypt(token)
        self.assertEqual(decoded["user"], payload["user"])
        self.assertAlmostEqual(decoded["exp"], payload["exp"], delta=2)

    def test_is_valid_true(self):
        payload = {"exp": time.time() + 3600, "user": "testuser"}
        token = self.token_mgr.encrypt(payload)
        self.assertTrue(self.token_mgr.is_valid(token))

    def test_is_valid_false(self):
        payload = {"exp": time.time() - 10, "user": "testuser"}
        token = self.token_mgr.encrypt(payload)
        self.assertFalse(self.token_mgr.is_valid(token))

if __name__ == "__main__":
    unittest.main()

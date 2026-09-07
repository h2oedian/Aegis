import unittest
from unittest.mock import patch

from aegis_sim.safety import UnsafeTargetError, validate_target


class TargetSafetyTests(unittest.TestCase):
    def test_allows_loopback_target(self):
        self.assertEqual(
            validate_target("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000",
        )

    def test_allows_private_target(self):
        self.assertEqual(validate_target("http://10.0.0.5"), "http://10.0.0.5")

    @patch("aegis_sim.safety.socket.getaddrinfo")
    def test_blocks_public_target_by_default(self, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        with self.assertRaises(UnsafeTargetError):
            validate_target("https://example.test")

    @patch("aegis_sim.safety.socket.getaddrinfo")
    def test_allows_explicitly_authorized_public_target(self, getaddrinfo):
        getaddrinfo.return_value = [(None, None, None, None, ("8.8.8.8", 443))]
        self.assertEqual(
            validate_target("https://example.test", allow_public_target=True),
            "https://example.test",
        )

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(UnsafeTargetError):
            validate_target("http://user:secret@127.0.0.1:8000")


if __name__ == "__main__":
    unittest.main()


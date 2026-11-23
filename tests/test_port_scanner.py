import unittest
from unittest.mock import patch

from ghostsec import port_scanner


class LegacyPortScannerTests(unittest.TestCase):
    def test_rejects_invalid_port_ranges_before_dns(self):
        invalid_ranges = (
            (0, 20),
            (1, 65536),
            (20, 10),
            (1, 1025),
            (True, 20),
            (1, 20.0),
        )
        for start, end in invalid_ranges:
            with self.subTest(start=start, end=end):
                with patch("ghostsec.socket.getaddrinfo") as resolver:
                    with self.assertRaises(ValueError):
                        port_scanner("127.0.0.1", start, end)
                    resolver.assert_not_called()

    def test_rejects_malformed_numeric_target_before_dns(self):
        with patch("ghostsec.socket.getaddrinfo") as resolver:
            with self.assertRaises(ValueError):
                port_scanner("127.0.01", 1, 20)
            resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()

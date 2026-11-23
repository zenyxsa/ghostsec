import unittest

from ghostsec_engine.agent_loop import _enforce_explicit_port_range


class PortRangeConstraintTests(unittest.TestCase):
    def test_accepts_requested_range(self):
        _enforce_explicit_port_range(
            "Scan ports 1 through 20.",
            [{"tool": "port_scan", "arguments": {
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 20,
            }}],
        )

    def test_rejects_changed_range(self):
        with self.assertRaisesRegex(ValueError, "requested 1-20"):
            _enforce_explicit_port_range(
                "Scan ports 1 through 20.",
                [{"tool": "port_scan", "arguments": {
                    "target": "127.0.0.1",
                    "start_port": 1,
                    "end_port": 80,
                }}],
            )

    def test_ignores_objectives_without_explicit_range(self):
        _enforce_explicit_port_range(
            "Perform a basic localhost assessment.",
            [{"tool": "port_scan", "arguments": {
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 80,
            }}],
        )


if __name__ == "__main__":
    unittest.main()

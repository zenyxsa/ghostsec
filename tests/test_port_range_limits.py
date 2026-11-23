import unittest

from ghostsec_engine.agent_loop import _enforce_explicit_port_range


class PortRangeLimitTests(unittest.TestCase):
    def test_rejects_nmap_when_objective_requires_bounded_ports(self):
        with self.assertRaisesRegex(ValueError, "cannot honor"):
            _enforce_explicit_port_range(
                "Scan ports 1 through 20 only.",
                [{"tool": "nmap_scan", "arguments": {"target": "127.0.0.1"}}],
            )

    def test_rejects_boolean_port_values(self):
        with self.assertRaisesRegex(ValueError, "invalid port range"):
            _enforce_explicit_port_range(
                "Scan ports range 1-20.",
                [{"tool": "port_scan", "arguments": {
                    "target": "127.0.0.1", "start_port": True, "end_port": 20,
                }}],
            )


if __name__ == "__main__":
    unittest.main()

import unittest

from ai_core.integrations import build_ghostsec_registry
from ai_core.tools import ToolContext, ToolError


class GhostSecIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def port_scanner(target, start_port, end_port):
            self.calls.append(("port", target, start_port, end_port))
            return {"target": target, "open_ports": [80]}

        def subdomain_finder(domain):
            self.calls.append(("subdomain", domain))
            return {"domain": domain, "subdomains": []}

        self.registry = build_ghostsec_registry(port_scanner, subdomain_finder)

    def test_port_scan_requires_confirmation_and_scope(self):
        args = {"target": "lab.local", "start_port": 1, "end_port": 100}

        with self.assertRaises(ToolError):
            self.registry.execute(
                "port_scan",
                args,
                ToolContext(authorized_targets=("lab.local",)),
            )

        with self.assertRaises(ToolError):
            self.registry.execute(
                "port_scan",
                args,
                ToolContext(
                    authorized_targets=("other.local",),
                    user_confirmed=True,
                ),
            )

        result = self.registry.execute(
            "port_scan",
            args,
            ToolContext(
                authorized_targets=("lab.local",),
                user_confirmed=True,
            ),
        )

        self.assertEqual(result["open_ports"], [80])
        self.assertEqual(len(self.calls), 1)

    def test_subdomain_discovery_uses_domain_scope(self):
        result = self.registry.execute(
            "subdomain_discovery",
            {"domain": "lab.example"},
            ToolContext(
                authorized_targets=("lab.example",),
                user_confirmed=True,
            ),
        )

        self.assertEqual(result["domain"], "lab.example")
        self.assertEqual(self.calls[0], ("subdomain", "lab.example"))

    def test_accepts_numeric_string_ports_from_model(self):
        result = self.registry.execute(
            "port_scan",
            {"target": "lab.local", "start_port": "22", "end_port": "22"},
            ToolContext(
                authorized_targets=("lab.local",),
                user_confirmed=True,
            ),
        )
        self.assertEqual(result["open_ports"], [80])
        self.assertEqual(self.calls, [("port", "lab.local", 22, 22)])
    def test_rejects_oversized_port_range(self):
        with self.assertRaises(ValueError):
            self.registry.execute(
                "port_scan",
                {"target": "lab.local", "start_port": 1, "end_port": 2000},
                ToolContext(
                    authorized_targets=("lab.local",),
                    user_confirmed=True,
                ),
            )

        self.assertEqual(self.calls, [])

    def test_rejects_invalid_port_arguments(self):
        context = ToolContext(
            authorized_targets=("lab.local",),
            user_confirmed=True,
        )

        for args in (
            {"target": "lab.local", "start_port": True, "end_port": 80},
            {"target": "lab.local", "start_port": 0, "end_port": 80},
            {"target": "lab.local", "start_port": 90, "end_port": 80},
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.registry.execute("port_scan", args, context)

        self.assertEqual(self.calls, [])

    def test_rejects_url_as_port_scan_target(self):
        target = "https://lab.local"

        with self.assertRaises(ValueError):
            self.registry.execute(
                "port_scan",
                {"target": target, "start_port": 1, "end_port": 80},
                ToolContext(
                    authorized_targets=(target,),
                    user_confirmed=True,
                ),
            )

        self.assertEqual(self.calls, [])

    def test_rejects_invalid_domains(self):
        for domain in ("https://example.com", "example", "example..com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                self.registry.execute(
                    "subdomain_discovery",
                    {"domain": domain},
                    ToolContext(
                        authorized_targets=(domain,),
                        user_confirmed=True,
                    ),
                )

        self.assertEqual(self.calls, [])

    def test_rejects_unresolved_port_scan(self):
        def unresolved_scanner(target, start_port, end_port):
            return None

        registry = build_ghostsec_registry(
            unresolved_scanner,
            lambda domain: {},
        )

        with self.assertRaises(RuntimeError):
            registry.execute(
                "port_scan",
                {"target": "lab.local", "start_port": 1, "end_port": 80},
                ToolContext(
                    authorized_targets=("lab.local",),
                    user_confirmed=True,
                ),
            )


if __name__ == "__main__":
    unittest.main()

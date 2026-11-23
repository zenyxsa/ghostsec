import unittest

from ai_core.targets import normalize_target


class TargetNormalizationTests(unittest.TestCase):
    def test_canonicalizes_ipv4(self):
        self.assertEqual(normalize_target("127.0.0.1"), "127.0.0.1")

    def test_rejects_noncanonical_numeric_ipv4_forms(self):
        for target in ("127.0.01", "127.1", "001.002.003.004"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target)

    def test_normalizes_hostname_case_and_trailing_dot(self):
        self.assertEqual(normalize_target("LAB.Example."), "lab.example")

    def test_scope_comparison_uses_normalized_target(self):
        from ai_core.tools import ToolContext, ToolRegistry, ToolSpec

        registry = ToolRegistry()
        registry.register(ToolSpec(
            name="probe",
            description="Mock authorized target check",
            handler=lambda target: target,
            required_args=("target",),
            allowed_args=("target",),
            target_arg="target",
        ))
        result = registry.execute(
            "probe",
            {"target": "lab.example"},
            ToolContext(
                authorized_targets=("LAB.EXAMPLE.",),
                user_confirmed=True,
            ),
        )
        self.assertEqual(result, "lab.example")

    def test_rejects_url_and_whitespace(self):
        for target in ("https://lab.example", "lab example", " lab.example"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target)

    def test_domain_requirement_rejects_single_label_and_ip(self):
        for target in ("localhost", "127.0.0.1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                normalize_target(target, require_dot=True)


if __name__ == "__main__":
    unittest.main()

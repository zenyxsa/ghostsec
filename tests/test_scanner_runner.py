import unittest
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import patch

from ghostsec_engine.tools import run_tool


class ScannerRunnerTests(unittest.TestCase):
    def test_rejects_unapproved_executables(self):
        for command in (
            ["python3", "-c", "print(1)"],
            ["/usr/bin/nmap", "127.0.0.1"],
            ["sh", "-c", "echo unsafe"],
        ):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    run_tool(command)

    def test_rejects_invalid_arguments(self):
        invalid_commands = (
            [],
            ["nmap", ""],
            ["nmap", 123],
            ["nmap", "bad\x00target"],
        )
        for command in invalid_commands:
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    run_tool(command)

    def test_rejects_invalid_timeouts(self):
        for timeout in (0, 301, True, 1.5):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    run_tool(["nmap", "127.0.0.1"], timeout=timeout)

    def test_allowlisted_command_runs_without_a_shell(self):
        fake = SimpleNamespace(stdout="mock scan output", stderr="")
        with patch("ghostsec_engine.tools.subprocess.run", return_value=fake) as runner:
            result = run_tool(["nmap", "127.0.0.1"], timeout=30)

        self.assertEqual(result, "mock scan output")
        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(runner.call_args.args[0], ["nmap", "127.0.0.1"])

    def test_shell_injection_text_is_passed_as_a_literal_argument(self):
        payload = "127.0.0.1; touch /tmp/ghostsec-injection-test"
        fake = SimpleNamespace(stdout="mock output", stderr="")

        with patch("ghostsec_engine.tools.subprocess.run", return_value=fake) as runner:
            run_tool(["nmap", payload])

        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(runner.call_args.args[0][1], payload)

    def test_timeout_is_reported(self):
        with patch(
            "ghostsec_engine.tools.subprocess.run",
            side_effect=TimeoutExpired(cmd=["nmap", "127.0.0.1"], timeout=5),
        ):
            result = run_tool(["nmap", "127.0.0.1"], timeout=5)

        self.assertIn("timed out", result.lower())


if __name__ == "__main__":
    unittest.main()

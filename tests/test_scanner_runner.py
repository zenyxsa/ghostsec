import unittest
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest.mock import patch

from ghostsec_engine.tools import ScannerExecutionError, run_tool


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
        for command in ([], ["nmap", ""], ["nmap", 123], ["nmap", "bad\x00target"]):
            with self.subTest(command=command), self.assertRaises(ValueError):
                run_tool(command)

    def test_rejects_invalid_timeouts(self):
        for timeout in (0, 301, True, 1.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                run_tool(["nmap", "127.0.0.1"], timeout=timeout)

    def test_allowlisted_command_runs_without_a_shell(self):
        fake = SimpleNamespace(stdout="mock scan output", stderr="", returncode=0)
        with patch("ghostsec_engine.tools.subprocess.run", return_value=fake) as runner:
            result = run_tool(["nmap", "127.0.0.1"], timeout=30)
        self.assertEqual(result, "mock scan output")
        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(runner.call_args.args[0], ["nmap", "127.0.0.1"])

    def test_shell_injection_text_is_passed_as_a_literal_argument(self):
        payload = "127.0.0.1; touch /tmp/ghostsec-injection-test"
        fake = SimpleNamespace(stdout="mock output", stderr="", returncode=0)
        with patch("ghostsec_engine.tools.subprocess.run", return_value=fake) as runner:
            run_tool(["nmap", payload])
        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(runner.call_args.args[0][1], payload)

    def test_timeout_raises_execution_error(self):
        with patch(
            "ghostsec_engine.tools.subprocess.run",
            side_effect=TimeoutExpired(cmd=["nmap", "127.0.0.1"], timeout=5),
        ):
            with self.assertRaisesRegex(ScannerExecutionError, "timed out"):
                run_tool(["nmap", "127.0.0.1"], timeout=5)

    def test_nonzero_exit_raises_execution_error_with_output(self):
        fake = SimpleNamespace(stdout="partial result", stderr="permission denied", returncode=2)
        with patch("ghostsec_engine.tools.subprocess.run", return_value=fake):
            with self.assertRaisesRegex(ScannerExecutionError, "status 2") as caught:
                run_tool(["nmap", "127.0.0.1"])
        self.assertIn("permission denied", str(caught.exception))
        self.assertIn("partial result", str(caught.exception))

    def test_missing_scanner_raises_execution_error(self):
        with patch("ghostsec_engine.tools.subprocess.run", side_effect=FileNotFoundError("nmap")):
            with self.assertRaisesRegex(ScannerExecutionError, "not installed"):
                run_tool(["nmap", "127.0.0.1"])

    def test_os_error_raises_execution_error(self):
        with patch("ghostsec_engine.tools.subprocess.run", side_effect=PermissionError("blocked")):
            with self.assertRaisesRegex(ScannerExecutionError, "execution failed"):
                run_tool(["nmap", "127.0.0.1"])


if __name__ == "__main__":
    unittest.main()

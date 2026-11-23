import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_core.analyst import _read_artifact, analyze_file
from ai_core.client import OllamaClient, OllamaError


class ArtifactTests(unittest.TestCase):
    def test_reads_json_as_pretty_text(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text(json.dumps({"open_ports": [22, 443]}), encoding="utf-8")
            result = _read_artifact(report)
            self.assertIn('"open_ports"', result)
            self.assertIn("443", result)

    def test_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                _read_artifact(report)

    def test_rejects_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            _read_artifact("does-not-exist-ghostsec.json")

    @patch("ai_core.analyst.OllamaClient")
    def test_analyze_file_sends_artifact_as_user_data(self, client_class):
        client_class.return_value.chat.return_value = "Report summary"
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "scan.txt"
            report.write_text("Port 443 open", encoding="utf-8")
            result = analyze_file(report)
        self.assertEqual(result, "Report summary")
        messages = client_class.return_value.chat.call_args.args[0]
        self.assertIn("Port 443 open", messages[1]["content"])
        self.assertEqual(messages[0]["role"], "system")


if __name__ == "__main__":
    unittest.main()

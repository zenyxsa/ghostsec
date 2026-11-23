import tempfile
import unittest

from ghostsec_engine.agent_loop import run_agentic_assessment
from ghostsec_engine.storage import create_session, get_session


class FakeClient:
    def chat(self, messages):
        return "Mock final report"


class FailingToolOrchestrator:
    def __init__(self):
        self.client = FakeClient()
        self.calls = 0

    def plan(self, request):
        self.calls += 1
        if self.calls == 1:
            return {
                "summary": "Inspect the authorized test host",
                "actions": [{
                    "tool": "nmap_scan",
                    "arguments": {"target": "127.0.0.1"},
                }],
            }
        return {"summary": "No further checks", "actions": []}

    def execute_approved(self, plan, context):
        return [{
            "tool": "nmap_scan",
            "ok": False,
            "error": "scanner not installed",
        }]


class PartialStatusTests(unittest.TestCase):
    def test_completed_planning_with_failed_tool_is_persisted_as_partial(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session(
                "127.0.0.1", "Failure test", ("127.0.0.1",), db_path=db_path
            )
            result = run_agentic_assessment(
                FailingToolOrchestrator(),
                "Assess localhost",
                ("127.0.0.1",),
                approve=lambda prompt: "YES",
                emit=lambda message: None,
                session_id=session_id,
                db_path=db_path,
            )
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(saved["status"], "partial")
            self.assertEqual(saved["risk_level"], "unknown")
            self.assertIn("ASSESSMENT PARTIAL - TOOL ERRORS", saved["report"])
            self.assertFalse(saved["tool_results"][0]["ok"])


if __name__ == "__main__":
    unittest.main()

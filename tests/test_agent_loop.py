import unittest
import json
import tempfile

from ghostsec_engine.storage import create_session, get_session
from ghostsec_engine.agent_loop import run_agentic_assessment


class FakeClient:
    def __init__(self, response="Mock final security assessment"):
        self.calls = []
        self.response = response

    def chat(self, messages):
        self.calls.append(messages)
        return self.response


class FakeOrchestrator:
    def __init__(self, plans, response="Mock final security assessment"):
        self.plans = list(plans)
        self.client = FakeClient(response)
        self.executed = []

    def plan(self, request):
        return self.plans.pop(0)

    def execute_approved(self, plan, context):
        self.executed.append((plan, context))
        return [{"tool": "nmap_scan", "ok": True, "result": "mock evidence"}]


class AgentLoopTests(unittest.TestCase):
    def make_plan(self):
        return {
            "summary": "Inspect the authorized localhost target",
            "actions": [{
                "tool": "nmap_scan",
                "arguments": {"target": "127.0.0.1"},
            }],
        }

    def test_runs_multiple_analysis_rounds(self):
        orchestrator = FakeOrchestrator([
            self.make_plan(),
            {"summary": "Evidence is sufficient", "actions": []},
        ])
        result = run_agentic_assessment(
            orchestrator,
            "Assess my local machine",
            ("127.0.0.1",),
            approve=lambda prompt: "YES",
            emit=lambda message: None,
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["rounds_completed"], 1)
        self.assertEqual(len(orchestrator.executed), 1)
        self.assertTrue(result["report"].endswith("Mock final security assessment"))
        self.assertTrue(orchestrator.executed[0][1].user_confirmed)

    def test_cancellation_executes_no_tools(self):
        orchestrator = FakeOrchestrator([self.make_plan()])
        result = run_agentic_assessment(
            orchestrator,
            "Assess my local machine",
            ("127.0.0.1",),
            approve=lambda prompt: "NO",
            emit=lambda message: None,
        )
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(orchestrator.executed, [])

    def test_requires_authorized_targets(self):
        orchestrator = FakeOrchestrator([])
        with self.assertRaises(ValueError):
            run_agentic_assessment(
                orchestrator, "Assess a target", (), emit=lambda message: None
            )

    def test_rejects_round_limit_above_nine(self):
        orchestrator = FakeOrchestrator([])
        with self.assertRaises(ValueError):
            run_agentic_assessment(
                orchestrator,
                "Assess localhost",
                ("127.0.0.1",),
                max_rounds=10,
                emit=lambda message: None,
            )


    def test_persists_completed_session_and_tool_results(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session(
                target="127.0.0.1",
                objective="Assess localhost",
                authorized_targets=("127.0.0.1",),
                db_path=db_path,
            )
            orchestrator = FakeOrchestrator([
                self.make_plan(),
                {"summary": "Evidence is sufficient", "actions": []},
            ])
            result = run_agentic_assessment(
                orchestrator,
                "Assess localhost",
                ("127.0.0.1",),
                approve=lambda prompt: "YES",
                emit=lambda message: None,
                session_id=session_id,
                db_path=db_path,
            )
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(result["session_id"], session_id)
            self.assertEqual(saved["status"], "completed")
            self.assertTrue(saved["report"].endswith("Mock final security assessment"))
            self.assertEqual(len(saved["tool_results"]), 1)
            self.assertEqual(saved["tool_results"][0]["result"], "mock evidence")

    def test_persists_cancelled_session(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session(
                target="127.0.0.1",
                objective="Assess localhost",
                authorized_targets=("127.0.0.1",),
                db_path=db_path,
            )
            orchestrator = FakeOrchestrator([self.make_plan()])
            result = run_agentic_assessment(
                orchestrator,
                "Assess localhost",
                ("127.0.0.1",),
                approve=lambda prompt: "NO",
                emit=lambda message: None,
                session_id=session_id,
                db_path=db_path,
            )
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(result["status"], "cancelled")
            self.assertEqual(saved["status"], "cancelled")
            self.assertTrue(saved["report"].endswith("Mock final security assessment"))
            self.assertEqual(saved["tool_results"], [])

    def test_marks_session_failed_when_planning_raises(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Failure test", ("127.0.0.1",), db_path=db_path)
            class FailingOrchestrator(FakeOrchestrator):
                def plan(self, request):
                    raise RuntimeError("mock planner failure")
            with self.assertRaisesRegex(RuntimeError, "mock planner failure"):
                run_agentic_assessment(FailingOrchestrator([]), "Assess localhost", ("127.0.0.1",), emit=lambda message: None, session_id=session_id, db_path=db_path)
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(saved["report"], "Assessment failed before a final report was generated.")

    def test_marks_session_cancelled_on_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Interrupt test", ("127.0.0.1",), db_path=db_path)
            class InterruptingOrchestrator(FakeOrchestrator):
                def plan(self, request):
                    raise KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                run_agentic_assessment(InterruptingOrchestrator([]), "Assess localhost", ("127.0.0.1",), emit=lambda message: None, session_id=session_id, db_path=db_path)
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(saved["status"], "cancelled")
            self.assertEqual(saved["report"], "Assessment interrupted by user.")

    def test_skips_duplicate_actions_across_rounds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Duplicate test", ("127.0.0.1",), db_path=db_path)
            orchestrator = FakeOrchestrator([self.make_plan(), self.make_plan()])
            approvals = []

            result = run_agentic_assessment(
                orchestrator, "Assess localhost", ("127.0.0.1",),
                approve=lambda prompt: approvals.append(prompt) or "YES",
                emit=lambda message: None,
                session_id=session_id, db_path=db_path,
            )

            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(len(orchestrator.executed), 1)
            self.assertEqual(len(approvals), 1)
            self.assertEqual(result["status"], "no_new_actions")
            self.assertEqual(saved["status"], "no_new_actions")
            self.assertEqual(len(saved["tool_results"]), 1)
            self.assertIn("ASSESSMENT STOPPED - NO NEW ACTIONS", saved["report"])

    def test_deduplicates_actions_within_same_round(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Same round duplicate test", ("127.0.0.1",), db_path=db_path)
            duplicate_plan = self.make_plan()
            duplicate_plan["actions"].append(dict(duplicate_plan["actions"][0]))
            orchestrator = FakeOrchestrator([
                duplicate_plan,
                {"summary": "Evidence is sufficient", "actions": []},
            ])

            result = run_agentic_assessment(
                orchestrator, "Assess localhost", ("127.0.0.1",),
                approve=lambda prompt: "YES",
                emit=lambda message: None,
                session_id=session_id, db_path=db_path,
            )

            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(len(orchestrator.executed), 1)
            self.assertEqual(len(orchestrator.executed[0][0]["actions"]), 1)
            self.assertEqual(len(saved["tool_results"]), 1)
            self.assertEqual(result["status"], "completed")
            self.assertIn("SCOPE LIMITATION", saved["report"])


    def test_persists_only_evidence_verified_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Structured report test", ("127.0.0.1",), db_path=db_path)
            structured = {
                "report": "A test service was observed. Further validation is recommended.",
                "risk_level": "medium",
                "findings": [
                    {
                        "name": "Observed test service",
                        "severity": "low",
                        "port": 8080,
                        "service": "test-http",
                        "description": "The scan output reports a test service.",
                        "evidence": "mock evidence",
                        "remediation": "Confirm whether the service is required and restrict access if not.",
                    },
                    {
                        "name": "Invented service",
                        "severity": "critical",
                        "port": 445,
                        "service": "SMB",
                        "description": "This was not present in the tool output.",
                        "evidence": "unseen external service on the network",
                        "remediation": "Disable the service.",
                    },
                ],
            }
            orchestrator = FakeOrchestrator(
                [self.make_plan(), {"summary": "Evidence is sufficient", "actions": []}],
                response=json.dumps(structured),
            )
            result = run_agentic_assessment(
                orchestrator, "Assess localhost", ("127.0.0.1",),
                approve=lambda prompt: "YES", emit=lambda message: None,
                session_id=session_id, db_path=db_path,
            )
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(saved["risk_level"], "medium")
            self.assertEqual(len(saved["findings"]), 1)
            self.assertEqual(saved["findings"][0]["name"], "Observed test service")
            self.assertEqual(len(saved["fixes"]), 1)
            self.assertEqual(saved["fixes"][0]["finding_id"], saved["findings"][0]["id"])
            self.assertIn("Omitted 1 proposed finding", saved["report"])

    def test_incomplete_assessment_does_not_store_model_risk_rating(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Cancelled report test", ("127.0.0.1",), db_path=db_path)
            structured = {
                "report": "One limited check was completed.",
                "risk_level": "low",
                "findings": [],
            }
            orchestrator = FakeOrchestrator([self.make_plan()], response=json.dumps(structured))
            run_agentic_assessment(
                orchestrator, "Assess localhost", ("127.0.0.1",),
                approve=lambda prompt: "NO", emit=lambda message: None,
                session_id=session_id, db_path=db_path,
            )
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(saved["status"], "cancelled")
            self.assertEqual(saved["risk_level"], "unknown")
            self.assertIn("ASSESSMENT CANCELLED - INCOMPLETE", saved["report"])

    def test_does_not_store_risk_without_successful_tool_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = temp_dir + "/history.db"
            session_id = create_session("127.0.0.1", "Failed tool test", ("127.0.0.1",), db_path=db_path)
            structured = {"report": "The check failed.", "risk_level": "low", "findings": []}
            class FailedToolOrchestrator(FakeOrchestrator):
                def execute_approved(self, plan, context):
                    self.executed.append((plan, context))
                    return [{"tool": "nmap_scan", "ok": False, "error": "mock failure"}]
            orchestrator = FailedToolOrchestrator([self.make_plan(), {"summary": "No more checks", "actions": []}], response=json.dumps(structured))
            run_agentic_assessment(orchestrator, "Assess localhost", ("127.0.0.1",), approve=lambda prompt: "YES", emit=lambda message: None, session_id=session_id, db_path=db_path)
            saved = get_session(session_id, db_path=db_path)
            self.assertEqual(saved["status"], "completed")
            self.assertEqual(saved["risk_level"], "unknown")
            self.assertEqual(saved["findings"], [])

if __name__ == "__main__":
    unittest.main()

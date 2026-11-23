import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from ghostsec_engine.storage import (
    create_session,
    complete_session,
    delete_session,
    get_session,
    initialize_database,
    list_sessions,
    record_tool_result,
    save_finding,
    save_fix,
)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "test.db"
        self.session_id = create_session(
            "127.0.0.1",
            "Localhost defensive assessment",
            ("127.0.0.1",),
            self.db,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_creates_and_lists_session(self):
        rows = list_sessions(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], self.session_id)
        self.assertEqual(rows[0]["target"], "127.0.0.1")
        self.assertEqual(rows[0]["status"], "running")

    def test_records_tool_result(self):
        result_id = record_tool_result(
            self.session_id, 1, "nmap_scan",
            {"target": "127.0.0.1"}, True,
            {"open_ports": [22]}, db_path=self.db,
        )
        session = get_session(self.session_id, self.db)
        self.assertIsNotNone(session)
        self.assertEqual(session["tool_results"][0]["id"], result_id)
        self.assertEqual(session["tool_results"][0]["result"], {"open_ports": [22]})

    def test_saves_finding_and_remediation(self):
        finding_id = save_finding(
            self.session_id, "Unnecessary open service",
            severity="low", port="22",
            description="Service is reachable on localhost.",
            evidence="Mock test evidence", db_path=self.db,
        )
        fix_id = save_fix(
            self.session_id, "Disable the service if it is not needed.",
            finding_id=finding_id, db_path=self.db,
        )
        session = get_session(self.session_id, self.db)
        self.assertEqual(session["findings"][0]["id"], finding_id)
        self.assertEqual(session["fixes"][0]["id"], fix_id)

    def test_completes_session_and_saves_report(self):
        complete_session(
            self.session_id, "completed", "Mock final report",
            risk_level="LOW", summary="No critical issues.",
            db_path=self.db,
        )
        session = get_session(self.session_id, self.db)
        self.assertEqual(session["status"], "completed")
        self.assertEqual(session["report"], "Mock final report")
        self.assertIsNotNone(session["completed_at"])

    def test_deletes_session_and_linked_records(self):
        save_finding(self.session_id, "Test finding", db_path=self.db)
        record_tool_result(
            self.session_id, 1, "nmap_scan",
            {"target": "127.0.0.1"}, True, "mock", db_path=self.db,
        )
        delete_session(self.session_id, self.db)
        self.assertIsNone(get_session(self.session_id, self.db))
        self.assertEqual(list_sessions(db_path=self.db), [])

    def test_rejects_fix_linked_to_another_session(self):
        other_id = create_session(
            "localhost", "Second session", ("localhost",), self.db,
        )
        finding_id = save_finding(other_id, "Other finding", db_path=self.db)
        with self.assertRaises(ValueError):
            save_fix(
                self.session_id, "Incorrect cross-session fix",
                finding_id=finding_id, db_path=self.db,
            )

    def test_rejects_empty_authorized_scope(self):
        with self.assertRaises(ValueError):
            create_session("localhost", "Test", (), self.db)


    def test_custom_database_does_not_change_parent_permissions(self):
        parent = self.db.parent
        original_mode = stat.S_IMODE(parent.stat().st_mode)
        os.chmod(parent, 0o755)

        try:
            custom_db = parent / "custom-permissions.db"
            initialize_database(custom_db)

            self.assertEqual(
                stat.S_IMODE(parent.stat().st_mode), 0o755
            )
            self.assertEqual(
                stat.S_IMODE(custom_db.stat().st_mode), 0o600
            )
        finally:
            os.chmod(parent, original_mode)

    def test_default_database_directory_is_private(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "private" / "ghostsec.db"

            with patch("ghostsec_engine.storage.DEFAULT_DB_PATH", db_path):
                initialize_database()

            self.assertEqual(
                stat.S_IMODE(db_path.parent.stat().st_mode), 0o700
            )
            self.assertEqual(
                stat.S_IMODE(db_path.stat().st_mode), 0o600
            )


if __name__ == "__main__":
    unittest.main()

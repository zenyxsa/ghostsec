import tempfile
import unittest
from pathlib import Path

from ghostsec_engine.export import export_html, export_session
from ghostsec_engine.storage import (
    complete_session,
    create_session,
    record_tool_result,
    save_finding,
    save_fix,
)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "test.db"
        self.out = self.root / "reports"
        self.session_id = create_session(
            "127.0.0.1", "Export HTML test", ("127.0.0.1",), db_path=self.db
        )
        record_tool_result(
            self.session_id, 1, "nmap_scan", {"target": "127.0.0.1"}, True,
            {"banner": "<script>alert(1)</script>"}, db_path=self.db,
        )
        finding_id = save_finding(
            self.session_id, "Unsafe <service>", severity="medium", port="8080",
            service="http", description="Evidence <img src=x>", db_path=self.db,
        )
        save_fix(
            self.session_id, "Update the <service> safely", finding_id=finding_id,
            db_path=self.db,
        )
        complete_session(
            self.session_id, "completed", "Report <script>blocked</script>",
            risk_level="MEDIUM", summary="Evidence is sufficient", db_path=self.db,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_exports_html_with_assessment_content_escaped(self):
        output = Path(export_html(self.session_id, self.out, db_path=self.db))
        self.assertTrue(output.is_file())
        content = output.read_text(encoding="utf-8")
        self.assertIn("GHOSTSEC", content)
        self.assertIn("Evidence is sufficient", content)
        self.assertIn("Unsafe &lt;service&gt;", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertIn("&lt;img src=x&gt;", content)
        self.assertIn("Update the &lt;service&gt; safely", content)
        self.assertNotIn("<script>alert(1)</script>", content)

    def test_rejects_missing_session(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            export_html(999999, self.out, db_path=self.db)

    def test_rejects_unknown_format(self):
        with self.assertRaisesRegex(ValueError, "format must be"):
            export_session(self.session_id, self.out, format="docx", db_path=self.db)


if __name__ == "__main__":
    unittest.main()

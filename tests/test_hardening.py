"""Hardening tests — error paths, edge cases, and bad-input handling."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mftparse.cli import main  # noqa: E402
from mftparse.core import analyze, parse_mft_csv  # noqa: E402

HEADER = (
    "EntryNumber,FileName,ParentPath,Extension,FileSize,IsDirectory,InUse,"
    "Created0x10,LastModified0x10,LastAccessed0x10,LastRecordChange0x10,"
    "Created0x30,LastModified0x30,LastAccessed0x30,LastRecordChange0x30\n"
)


class TestParseMftCsvEdgeCases(unittest.TestCase):
    """Edge-case and error-path tests for parse_mft_csv."""

    def test_empty_string_returns_empty_list(self):
        """Whitespace / empty input must return [] without raising."""
        self.assertEqual(parse_mft_csv(""), [])
        self.assertEqual(parse_mft_csv("   \n  "), [])

    def test_header_only_returns_empty_list(self):
        """A CSV with only a header row and no data rows returns []."""
        result = parse_mft_csv(HEADER)
        self.assertEqual(result, [])

    def test_all_blank_data_rows_skipped(self):
        """Rows that are entirely blank are silently skipped."""
        csv_text = HEADER + ",,,,,,,,,,,,,,,\n"
        result = parse_mft_csv(csv_text)
        self.assertEqual(result, [])

    def test_non_string_input_raises_type_error(self):
        """Passing a non-str (bytes, None) must raise TypeError."""
        with self.assertRaises(TypeError):
            parse_mft_csv(b"some bytes")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            parse_mft_csv(None)  # type: ignore[arg-type]

    def test_missing_timestamp_columns_tolerated(self):
        """A CSV with no timestamp columns must parse without raising."""
        csv_text = "EntryNumber,FileName,FileSize\n1,test.exe,1024\n"
        records = parse_mft_csv(csv_text)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].si_created)
        self.assertIsNone(records[0].fn_created)

    def test_malformed_entry_number_tolerated(self):
        """A non-integer entry number must not crash — entry becomes None."""
        suffix = ",,,,,,,\n"
        csv_text = HEADER + "NOT_AN_INT,foo.exe,C:\\Temp,.exe,100,False,True," + suffix
        records = parse_mft_csv(csv_text)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].entry)

    def test_malformed_size_tolerated(self):
        """A non-integer file size must not crash — size becomes None."""
        suffix = ",,,,,,,\n"
        csv_text = HEADER + "42,foo.exe,C:\\Temp,.exe,NOT_SIZE,False,True," + suffix
        records = parse_mft_csv(csv_text)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].size)


class TestAnalyzeEdgeCases(unittest.TestCase):
    """Edge cases in the analyze() pipeline."""

    def test_analyze_empty_list(self):
        """analyze([]) must return a zero-finding result without raising."""
        result = analyze([])
        self.assertEqual(result.total_records, 0)
        self.assertEqual(result.findings, [])
        self.assertFalse(result.has_findings)

    def test_analyze_record_with_all_none_timestamps(self):
        """A record with all timestamps None should not produce findings."""
        row = "1,foo.exe,C:\\Temp,.exe,100,False,True,,,,,,,,\n"
        records = parse_mft_csv(HEADER + row)
        result = analyze(records)
        # Timestomp rules need actual timestamps — no false positives on None
        ts_rules = {
            f.rule for f in result.findings
            if f.rule.startswith("timestomp_")
        }
        self.assertEqual(ts_rules, set())


class TestCliErrorPaths(unittest.TestCase):
    """CLI must handle bad input gracefully — no raw tracebacks."""

    def test_missing_file_returns_exit_2(self):
        """A non-existent input file must print an error and return 2."""
        rc = main(["analyze", "/no/such/file/here.csv"])
        self.assertEqual(rc, 2)

    def test_no_subcommand_returns_exit_2(self):
        """No subcommand must return 2 (already tested in smoke; kept here
        to ensure the hardened path still holds)."""
        self.assertEqual(main([]), 2)

    def test_empty_csv_file_exits_cleanly(self):
        """An empty CSV file must produce a clean 0 exit (no findings)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(HEADER)
            tmp = fh.name
        try:
            rc = main(["analyze", tmp, "--format", "json"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(tmp)

    def test_json_output_on_empty_input(self):
        """JSON output on an all-header CSV must be valid JSON with 0 findings."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(HEADER)
            tmp = fh.name
        import io as _io
        from contextlib import redirect_stdout
        buf = _io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = main(["analyze", tmp, "--format", "json"])
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["summary"]["finding_count"], 0)
        finally:
            os.unlink(tmp)

    def test_output_to_file(self):
        """Writing the report to a -o file must succeed and create the file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(HEADER)
            tmp_in = fh.name
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        ) as fh:
            tmp_out = fh.name
        try:
            rc = main(["analyze", tmp_in, "--format", "json", "-o", tmp_out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(tmp_out))
            with open(tmp_out, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("findings", data)
        finally:
            os.unlink(tmp_in)
            os.unlink(tmp_out)


class TestMcpServerImport(unittest.TestCase):
    """mcp_server must be importable without errors."""

    def test_mcp_server_importable(self):
        """Importing mcp_server must not raise (the real MCP package is
        optional and not installed — only the top-level import is tested)."""
        try:
            from mftparse import mcp_server  # noqa: F401
        except ImportError as exc:
            self.fail(f"mcp_server failed to import: {exc}")


if __name__ == "__main__":
    unittest.main()

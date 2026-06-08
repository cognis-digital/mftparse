"""Smoke tests for MFTPARSE — no network, standard library only."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mftparse import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze,
    parse_mft_csv,
    render_html,
    render_json,
    render_table,
)
from mftparse.cli import main  # noqa: E402

HEADER = (
    "EntryNumber,FileName,ParentPath,Extension,FileSize,IsDirectory,InUse,"
    "Created0x10,LastModified0x10,LastAccessed0x10,LastRecordChange0x10,"
    "Created0x30,LastModified0x30,LastAccessed0x30,LastRecordChange0x30\n"
)

CLEAN_ROW = (
    "512,kernel32.dll,C:\\Windows\\System32,.dll,1052160,False,True,"
    "2024-01-01 08:01:12.654321,2024-01-01 08:01:12.654321,"
    "2024-05-02 09:11:00.111111,2024-01-01 08:01:12.654321,"
    "2024-01-01 08:01:12.654321,2024-01-01 08:01:12.654321,"
    "2024-01-01 08:01:12.654321,2024-01-01 08:01:12.654321\n"
)

TIMESTOMP_ROW = (
    "9001,svch0st.exe,C:\\Users\\victim\\AppData\\Roaming,.exe,245760,False,True,"
    "2009-07-14 01:14:00.000000,2009-07-14 01:14:00.000000,"
    "2024-05-20 22:00:00.000000,2024-05-20 22:00:01.000000,"
    "2024-05-20 21:59:58.778899,2024-05-20 21:59:58.778899,"
    "2024-05-20 21:59:58.778899,2024-05-20 21:59:58.778899\n"
)

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "sample_mft.csv")


class TestParse(unittest.TestCase):
    def test_version_present(self):
        self.assertEqual(TOOL_NAME, "mftparse")
        self.assertTrue(TOOL_VERSION)

    def test_parse_basic(self):
        recs = parse_mft_csv(HEADER + CLEAN_ROW)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.entry, 512)
        self.assertEqual(r.name, "kernel32.dll")
        self.assertEqual(r.ext_lower, ".dll")
        self.assertEqual(r.full_path, "C:\\Windows\\System32\\kernel32.dll")
        self.assertIsNotNone(r.si_created)

    def test_clean_no_findings(self):
        result = analyze(parse_mft_csv(HEADER + CLEAN_ROW))
        self.assertFalse(result.has_findings)


class TestDetections(unittest.TestCase):
    def test_timestomp_detected(self):
        result = analyze(parse_mft_csv(HEADER + TIMESTOMP_ROW))
        rules = {f.rule for f in result.findings}
        self.assertIn("timestomp_si_before_fn", rules)
        self.assertIn("timestomp_zeroed_subsecond", rules)

    def test_double_extension(self):
        row = (
            "9003,Invoice_2024.pdf.exe,C:\\Users\\v\\Downloads,.exe,512000,"
            "False,True,2024-05-20 22:10:00.1,2024-05-20 22:10:00.1,"
            "2024-05-20 22:10:00.1,2024-05-20 22:10:00.1,2024-05-20 22:10:00.1,"
            "2024-05-20 22:10:00.1,2024-05-20 22:10:00.1,2024-05-20 22:10:00.1\n"
        )
        result = analyze(parse_mft_csv(HEADER + row))
        self.assertIn("double_extension_masquerade", {f.rule for f in result.findings})

    def test_suspicious_location(self):
        row = (
            "9002,update.exe,C:\\Windows\\Temp,.exe,1,False,True,"
            "2024-05-20 22:05:10.4,2024-05-20 22:05:10.4,2024-05-20 22:05:10.4,"
            "2024-05-20 22:05:10.4,2024-05-20 22:05:10.4,2024-05-20 22:05:10.4,"
            "2024-05-20 22:05:10.4,2024-05-20 22:05:10.4\n"
        )
        result = analyze(parse_mft_csv(HEADER + row))
        self.assertIn("executable_in_suspicious_dir", {f.rule for f in result.findings})

    def test_rtlo(self):
        row = (
            "9005,report‮doc.exe,C:\\Users\\v\\Downloads,.exe,1,False,True,"
            "2024-05-20 22:20:00.0,2024-05-20 22:20:00.0,2024-05-20 22:20:00.0,"
            "2024-05-20 22:20:00.0,2024-05-20 22:20:00.5,2024-05-20 22:20:00.5,"
            "2024-05-20 22:20:00.5,2024-05-20 22:20:00.5\n"
        )
        result = analyze(parse_mft_csv(HEADER + row))
        self.assertIn("rtlo_filename", {f.rule for f in result.findings})


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.result = analyze(parse_mft_csv(HEADER + TIMESTOMP_ROW + CLEAN_ROW))

    def test_table(self):
        out = render_table(self.result)
        self.assertIn("MFTPARSE", out)
        self.assertIn("svch0st.exe", out)

    def test_json_valid(self):
        import json
        data = json.loads(render_json(self.result))
        self.assertEqual(data["tool"], "mftparse")
        self.assertTrue(data["findings"])

    def test_html(self):
        out = render_html(self.result)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("MFTPARSE", out)


class TestCli(unittest.TestCase):
    def test_demo_exits_nonzero(self):
        if not os.path.exists(DEMO):
            self.skipTest("demo file missing")
        rc = main(["analyze", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_no_command(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()

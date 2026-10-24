#!/usr/bin/env python3
"""Tests for the launcher's confirmation-gated ignored-file cleanup."""
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import solve  # noqa: E402


class CleanIgnoredTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lab_clean_test_")
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / ".gitignore").write_text("evidence/\n.venv/\n*.tmp\n")
        (self.root / "README.md").write_text("tracked context\n")
        (self.root / "draft.md").write_text("non-ignored file\n")
        (self.root / "evidence").mkdir()
        (self.root / "evidence" / "response.html").write_text("private data\n")
        (self.root / ".venv").mkdir()
        (self.root / ".venv" / "state.tmp").write_text("generated\n")
        subprocess.run(["git", "-C", str(self.root), "add", ".gitignore", "README.md"], check=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_preview_and_cancel_leave_all_files_untouched(self):
        candidates, removed = solve.clean_ignored(str(self.root), confirm=False)
        self.assertFalse(removed)
        self.assertTrue(any("evidence" in item for item in candidates))
        self.assertTrue((self.root / "evidence" / "response.html").exists())
        self.assertTrue((self.root / ".venv" / "state.tmp").exists())
        self.assertTrue((self.root / "draft.md").exists())

    def test_confirmed_clean_removes_only_ignored_untracked_files(self):
        candidates, removed = solve.clean_ignored(str(self.root), confirm=True)
        self.assertTrue(removed)
        self.assertTrue(candidates)
        self.assertFalse((self.root / "evidence").exists())
        self.assertFalse((self.root / ".venv").exists())
        self.assertTrue((self.root / "README.md").exists())
        self.assertTrue((self.root / "draft.md").exists())

    def test_clean_aborts_if_ignored_paths_change_after_preview(self):
        preview, _ = solve.clean_ignored(str(self.root), confirm=False)
        (self.root / "late.tmp").write_text("appeared after preview")
        with self.assertRaises(RuntimeError):
            solve.clean_ignored(str(self.root), confirm=True, expected=preview)
        self.assertTrue((self.root / "evidence" / "response.html").exists())
        self.assertTrue((self.root / "late.tmp").exists())

    def test_cli_confirm_removes_ignored_files_only(self):
        old_file = solve.__file__
        output = StringIO()
        try:
            solve.__file__ = str(self.root / "solve.py")
            with patch.object(sys, "argv", ["solve.py", "--clean"]), patch("builtins.input", return_value="yes"), redirect_stdout(output):
                code = solve.main()
        finally:
            solve.__file__ = old_file
        self.assertEqual(code, 0)
        self.assertIn("Removed ignored untracked files", output.getvalue())
        self.assertFalse((self.root / "evidence").exists())
        self.assertFalse((self.root / ".venv").exists())
        self.assertTrue((self.root / "README.md").exists())
        self.assertTrue((self.root / "draft.md").exists())

    def test_cli_cancel_keeps_ignored_files(self):
        old_file = solve.__file__
        output = StringIO()
        try:
            solve.__file__ = str(self.root / "solve.py")
            with patch.object(sys, "argv", ["solve.py", "--clean"]), patch("builtins.input", return_value="n"), redirect_stdout(output):
                code = solve.main()
        finally:
            solve.__file__ = old_file
        self.assertEqual(code, 0)
        self.assertIn("Cancelled; nothing removed", output.getvalue())
        self.assertTrue((self.root / "evidence" / "response.html").exists())

    def test_refuses_non_repository_path(self):
        with tempfile.TemporaryDirectory(prefix="not_a_git_repo_") as other:
            with self.assertRaises(ValueError):
                solve.clean_ignored(other, confirm=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

import os
import runpy
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class RuntimeConfigTests(unittest.TestCase):
    def load(self, env):
        dotenv = types.ModuleType("dotenv")
        dotenv.load_dotenv = lambda: None
        with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, {"dotenv": dotenv}):
            return runpy.run_path(str(ROOT / "app/config.py"))

    def test_missing_or_blank_required_values_fail_closed(self):
        for env in ({}, {"MONGO_URI": "test-only"}, {"MONGO_URI": "test-only", "SECRET_KEY": "  "}):
            with self.subTest(env=env), self.assertRaisesRegex(RuntimeError, "runtime environment"):
                self.load(env)

    def test_explicit_environment_is_used_and_env_is_untracked(self):
        config = self.load({"MONGO_URI": "test-only-uri", "SECRET_KEY": "test-only-secret"})["Config"]
        self.assertEqual(config.MONGO_URI, "test-only-uri")
        self.assertEqual(config.SECRET_KEY, "test-only-secret")
        self.assertNotEqual(subprocess.run(["git", "ls-files", "--error-unmatch", ".env"], cwd=ROOT, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(["git", "check-ignore", "-q", ".env"], cwd=ROOT, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()

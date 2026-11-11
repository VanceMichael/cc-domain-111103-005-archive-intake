import json
import unittest
from pathlib import Path
from app.archive import inspect_archive
class DomainTests(unittest.TestCase):
    def test_manifest(self): self.assertEqual(inspect_archive("fixtures/package.zip")[1]["issuer"],"synthetic-lab")
    def test_members(self): self.assertIn("observations/data.json",[x["name"] for x in inspect_archive("fixtures/package.zip")[0]])
    def test_digest(self): self.assertEqual(len(inspect_archive("fixtures/package.zip")[0][0]["sha256"]),64)

class FixtureTests(unittest.TestCase):
    def test_fixture_directory(self): self.assertTrue(Path("fixtures").is_dir())

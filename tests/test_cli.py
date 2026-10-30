import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import serve, test_app

CLI = Path(__file__).resolve().parents[1] / "sbom-cli"
EXAMPLE = CLI.parent / "examples" / "app.json"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.endpoint = serve(self, test_app(self))
        self.source = Path(self.temp.name) / "app.json"
        self.source.write_text(EXAMPLE.read_text())

    def run_cli(self, *args, success=True):
        result = subprocess.run(
            [sys.executable, str(CLI), "--endpoint", self.endpoint, *map(str, args)],
            capture_output=True,
            text=True,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_ingest_and_query_across_processes(self):
        self.assertEqual(self.run_cli("ingest", self.source)["components"], 2)
        rows = self.run_cli("query", "--component", "requests")
        self.assertEqual(rows[0]["component"], "requests")
        self.assertEqual(rows[0]["version"], "2.32.3")
        self.assertEqual([r["document"] for r in rows], ["example-app"])
        self.assertEqual(
            len(
                self.run_cli("query", "--component", "requests", "--version", "2.32.3")
            ),
            1,
        )
        self.assertEqual(
            self.run_cli("query", "--component", "requests", "--version", "0"), []
        )
        self.assertEqual(len(self.run_cli("query", "--component", "REQUEST")), 1)
        rows = self.run_cli("query", "--license", "Apache-2.0")
        self.assertEqual(rows[0]["component"], "requests")
        self.assertEqual(rows[0]["license"], "Apache-2.0")
        self.assertEqual(rows[0]["document"], "example-app")
        self.assertEqual(self.run_cli("query", "--license", "MIT"), [])

    def test_list_components_and_licenses(self):
        self.assertEqual(self.run_cli("list-components"), [])
        self.assertEqual(self.run_cli("list-licenses"), [])
        self.run_cli("ingest", self.source)
        rows = self.run_cli("list-components")
        self.assertEqual([row["component"] for row in rows], ["click", "requests"])
        self.assertEqual(rows[1]["version"], "2.32.3")
        self.assertEqual(rows[1]["licenses"], ["Apache-2.0"])
        self.assertTrue(all(row["document"] == "example-app" for row in rows))
        self.assertEqual(self.run_cli("list-licenses"), ["Apache-2.0", "BSD-3-Clause"])
        self.assertEqual(
            len(self.run_cli("query", "--component", "EQUEST", "--version", "2.32.3")),
            1,
        )

    def test_auto_detected_formats_ingest_and_query(self):
        for filename, document in (
            ("syft.json", "syft-app"),
            ("spdx.json", "spdx-app"),
        ):
            with self.subTest(format=filename):
                # The same arbitrary filename also verifies replacement across formats.
                self.source.write_text((CLI.parent / "examples" / filename).read_text())
                result = self.run_cli("ingest", self.source)
                self.assertEqual(result, {"document": document, "components": 1})
                self.assertEqual(
                    self.run_cli(
                        "query", "--component", "requests", "--version", "2.32.3"
                    )[0]["document"],
                    document,
                )
                rows = self.run_cli("query", "--license", "Apache-2.0")
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["document"], document)
        self.source.write_text('{"spdxVersion":"SPDX-2.3","packages":[{}]}')
        self.run_cli("ingest", self.source, success=False)
        self.assertEqual(
            self.run_cli("query", "--component", "requests")[0]["document"], "spdx-app"
        )

    def test_multiple_documents_and_replacement(self):
        self.run_cli("ingest", self.source)
        other = Path(self.temp.name) / "other.json"
        data = json.loads(self.source.read_text())
        data["metadata"]["component"]["name"] = "other-app"
        other.write_text(json.dumps(data))
        self.run_cli("ingest", other)
        self.assertEqual(len(self.run_cli("query", "--component", "requests")), 2)
        self.run_cli("ingest", self.source)
        self.assertEqual(len(self.run_cli("query", "--component", "requests")), 2)
        data["components"] = []
        self.source.write_text(json.dumps(data))
        self.run_cli("ingest", self.source)
        self.assertEqual(len(self.run_cli("query", "--component", "requests")), 1)

    def test_nested_components_and_license_forms(self):
        self.source.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "name": "parent",
                            "components": [
                                {
                                    "name": "child",
                                    "licenses": [{"license": {"name": "Custom"}}],
                                },
                                {
                                    "name": "expression",
                                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                                },
                            ],
                        }
                    ],
                }
            )
        )
        self.run_cli("ingest", self.source)
        rows = self.run_cli("query", "--license", "Custom")
        self.assertEqual(rows[0]["component"], "child")
        self.assertEqual(rows[0]["document"], "app.json")
        self.assertIsNone(rows[0]["version"])
        self.assertEqual(
            len(self.run_cli("query", "--license", "MIT OR Apache-2.0")), 1
        )
        self.assertEqual(self.run_cli("query", "--license", "MIT"), [])

    def test_invalid_input_preserves_previous_ingestion(self):
        self.run_cli("ingest", self.source)
        for invalid in [
            "{",
            "[]",
            '{"bomFormat": "SPDX"}',
            '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"partial"},{}]}',
        ]:
            self.source.write_text(invalid)
            self.run_cli("ingest", self.source, success=False)
            self.assertEqual(len(self.run_cli("query", "--component", "requests")), 1)
        self.run_cli("ingest", Path(self.temp.name) / "missing.json", success=False)

    def test_database_administration_options_are_not_available(self):
        self.run_cli("init-db", success=False)
        self.run_cli(
            "--db", "sbom.db", "query", "--component", "requests", success=False
        )

    def test_query_argument_validation_and_empty_database(self):
        self.assertEqual(self.run_cli("query", "--component", "absent"), [])
        self.run_cli("query", success=False)
        self.run_cli("query", "--license", "MIT", "--version", "1", success=False)
        self.run_cli("query", "--license", "MIT", "--component", "x", success=False)


if __name__ == "__main__":
    unittest.main()

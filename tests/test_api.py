import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import serve, test_app

ROOT = Path(__file__).resolve().parents[1]


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app = test_app(self)
        self.client = self.app.test_client()

    def upload(self, data, source="test-source", filename="app.json"):
        return self.client.post(
            "/ingest",
            query_string={"source": source, "filename": filename},
            data=data,
            content_type="application/json",
        )

    def test_catalog_routes_and_partial_component_search(self):
        self.assertEqual(self.client.get("/components").json, [])
        self.assertEqual(self.client.get("/licenses").json, [])
        self.upload((ROOT / "examples" / "app.json").read_bytes())
        components = self.client.get("/components")
        self.assertEqual(components.status_code, 200)
        self.assertEqual(
            [row["component"] for row in components.json], ["click", "requests"]
        )
        self.assertEqual(
            self.client.get("/licenses").json, ["Apache-2.0", "BSD-3-Clause"]
        )
        self.assertEqual(
            self.client.get("/query?component=EQUEST&version=2.32.3").json,
            [
                {
                    "component": "requests",
                    "version": "2.32.3",
                    "document": "example-app",
                    "source": "test-source",
                }
            ],
        )
        self.assertEqual(self.client.get("/components?unknown=x").status_code, 400)
        self.assertEqual(self.client.get("/licenses?unknown=x").status_code, 400)

    def test_pitloom_spdx3_ingest_and_queries(self):
        response = self.upload(
            (ROOT / "examples" / "pitloom-0.22.0.spdx3.json").read_bytes()
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json, {"document": "pitloom", "components": 27})
        self.assertEqual(
            self.client.get("/query?component=pitloom&version=0.22.0").json,
            [
                {
                    "component": "pitloom",
                    "version": "0.22.0",
                    "document": "pitloom",
                    "source": "test-source",
                }
            ],
        )
        self.assertEqual(
            self.client.get("/query?component=pitloom&version=absent").json, []
        )
        licenses = self.client.get("/query?license=Apache-2.0").json
        self.assertTrue(
            any(
                row["component"] == "pitloom" and row["document"] == "pitloom"
                for row in licenses
            )
        )

    def test_init_database_command_preserves_documents(self):
        self.assertEqual(
            self.upload((ROOT / "examples" / "app.json").read_bytes()).status_code, 200
        )
        result = self.app.test_cli_runner().invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Database initialized", result.output)
        self.assertEqual(len(self.client.get("/query?component=requests").json), 1)

    def test_all_formats_and_queries(self):
        for filename, name in (
            ("app.json", "example-app"),
            ("syft.json", "syft-app"),
            ("spdx.json", "spdx-app"),
        ):
            with self.subTest(filename=filename):
                response = self.upload((ROOT / "examples" / filename).read_bytes())
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json["document"], name)
                rows = self.client.get(
                    "/query",
                    query_string={"component": "requests", "version": "2.32.3"},
                ).json
                self.assertEqual(
                    rows,
                    [
                        {
                            "component": "requests",
                            "version": "2.32.3",
                            "document": name,
                            "source": "test-source",
                        }
                    ],
                )
                rows = self.client.get("/query?license=Apache-2.0").json
                self.assertEqual(rows[0]["component"], "requests")
                self.assertEqual(rows[0]["license"], "Apache-2.0")
                self.assertEqual(
                    self.client.get("/query?component=requests&version=absent").json, []
                )

    def test_invalid_upload_rolls_back_and_filename_fallback(self):
        self.assertEqual(
            self.upload(
                b'{"spdxVersion":"SPDX-2.3","packages":[{"name":"original"}]}'
            ).status_code,
            200,
        )
        invalid = b'{"spdxVersion":"SPDX-2.3","packages":[{"name":"partial"},{}]}'
        self.assertEqual(self.upload(invalid).status_code, 400)
        self.assertEqual(self.client.get("/query?component=partial").json, [])
        self.assertEqual(
            self.client.get("/query?component=original").json[0]["document"], "app.json"
        )
        self.assertEqual(self.upload(b"{").status_code, 400)

    def test_upload_reads_bounded_chunks(self):
        class BoundedStream(io.BytesIO):
            def readinto(self, buffer):
                if len(buffer) > 64 * 1024:
                    raise AssertionError("unbounded upload read")
                return super().readinto(buffer)

        data = (ROOT / "examples" / "app.json").read_bytes()
        response = self.client.open(
            "/ingest?source=streamed",
            method="POST",
            input_stream=BoundedStream(data),
            content_length=len(data),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)

    def test_validation_and_json_errors(self):
        for route in (
            "/query",
            "/query?component=x&license=MIT",
            "/query?license=MIT&version=1",
            "/query?component=",
            "/query?component=x&unknown=y",
            "/query?component=x&component=y",
        ):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 400, route)
            self.assertIn("error", response.json)
        self.assertEqual(self.client.post("/ingest", data="{}").status_code, 415)
        self.assertEqual(
            self.client.post(
                "/ingest", data="{}", content_type="application/json"
            ).status_code,
            400,
        )
        self.assertEqual(self.upload(b"{}", filename="../escape.json").status_code, 400)
        self.assertEqual(self.client.get("/missing").status_code, 404)
        self.assertEqual(self.client.get("/health").json, {"status": "ok"})

    def test_remote_cli_matches_api_results(self):
        endpoint = serve(self, self.app)
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("SBOM_DATABASE", "SBOM_ENDPOINT")
        }

        def cli(*args):
            return subprocess.run(
                [sys.executable, str(ROOT / "sbom-cli"), *args],
                capture_output=True,
                text=True,
                env=env,
            )

        result = cli(
            "--endpoint", endpoint, "ingest", str(ROOT / "examples" / "app.json")
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        remote = cli("--endpoint", endpoint, "query", "--license", "Apache-2.0")
        expected = self.client.get("/query?license=Apache-2.0").json
        self.assertEqual(remote.returncode, 0, remote.stderr)
        self.assertEqual(json.loads(remote.stdout), expected)
        env["SBOM_ENDPOINT"] = endpoint
        self.assertEqual(cli("query", "--component", "requests").returncode, 0)
        self.assertNotEqual(cli("--endpoint", endpoint, "init-db").returncode, 0)
        self.assertNotEqual(
            cli(
                "--endpoint", endpoint, "--db", "unused", "query", "--component", "x"
            ).returncode,
            0,
        )
        missing = cli("--endpoint", endpoint + "/missing", "query", "--component", "x")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("HTTP 404", missing.stderr)
        self.assertNotIn("Traceback", missing.stderr)

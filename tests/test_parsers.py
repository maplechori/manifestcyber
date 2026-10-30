import json
import tempfile
import tracemalloc
import unittest
from pathlib import Path

from parsers import parse_sbom


class ParserTests(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "no-format-hint.txt"
            path.write_text(json.dumps(data))
            name, components = parse_sbom(path)
            return name, list(components)

    def test_spdx_versions_licenses_and_missing_version(self):
        for version in ("SPDX-2.2", "SPDX-2.3", "SPDX-2.3.1"):
            with self.subTest(version=version):
                name, components = self.parse(
                    {
                        "spdxVersion": version,
                        "name": "app",
                        "packages": [
                            {
                                "name": "a",
                                "versionInfo": "1",
                                "licenseDeclared": "MIT",
                                "licenseConcluded": "MIT",
                            },
                            {
                                "name": "b",
                                "licenseDeclared": "NONE",
                                "licenseConcluded": "NOASSERTION",
                            },
                            {
                                "name": "c",
                                "licenseDeclared": "MIT OR Apache-2.0",
                                "licenseConcluded": "Custom",
                            },
                        ],
                    }
                )
                self.assertEqual(name, "app")
                self.assertEqual(
                    components,
                    [
                        ("a", "1", ["MIT"]),
                        ("b", None, []),
                        ("c", None, ["Custom", "MIT OR Apache-2.0"]),
                    ],
                )

    def test_syft_licenses_and_filename_fallback(self):
        name, components = self.parse(
            {
                "descriptor": {"name": "syft"},
                "artifacts": [
                    {
                        "name": "a",
                        "licenses": [
                            {"value": "MIT License", "spdxExpression": "MIT"},
                            {"value": "MIT"},
                        ],
                    },
                    {"name": "b", "licenses": None},
                    {"name": "c", "licenses": [{"value": "Custom"}]},
                ],
            }
        )
        self.assertEqual(name, "no-format-hint.txt")
        self.assertEqual(
            components, [("a", None, ["MIT"]), ("b", None, []), ("c", None, ["Custom"])]
        )

    def test_empty_documents_and_syft_schema_detection(self):
        for data in (
            {"spdxVersion": "SPDX-2.3", "packages": []},
            {
                "schema": {
                    "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema.json"
                },
                "artifacts": [],
            },
        ):
            self.assertEqual(self.parse(data), ("no-format-hint.txt", []))

    def test_malformed_and_unknown_formats(self):
        for data in (
            {},
            [],
            {"artifacts": []},
            {"spdxVersion": "SPDX-3.0"},
            {"bomFormat": "CycloneDX", "specVersion": "9"},
            {"spdxVersion": "SPDX-2.3", "packages": None},
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "x", "versionInfo": 1}]},
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [{"name": "x", "licenseDeclared": []}],
            },
            {"descriptor": {"name": "syft"}},
            {"descriptor": {"name": "syft"}, "source": [], "artifacts": []},
            {
                "descriptor": {"name": "syft"},
                "artifacts": [{"name": "x", "licenses": [{}]}],
            },
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.parse(data)

    def test_pitloom_spdx3_sample(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "examples"
            / "pitloom-0.22.0.spdx3.json"
        )
        name, components = parse_sbom(path)
        rows = list(components)
        self.assertEqual(name, "pitloom")
        self.assertEqual(len(rows), 27)
        self.assertIn(("pitloom", "0.22.0", ["Apache-2.0"]), rows)
        self.assertTrue(any("MIT" in licenses for _, _, licenses in rows))

    def test_spdx3_order_independent_license_references(self):
        graph = [
            {
                "type": "Relationship",
                "from": "package",
                "relationshipType": "hasDeclaredLicense",
                "to": ["license"],
            },
            {
                "type": "Relationship",
                "from": "package",
                "relationshipType": "hasConcludedLicense",
                "to": [
                    "license",
                    "custom",
                    "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement",
                ],
            },
            {
                "type": "software_Package",
                "spdxId": "package",
                "name": "test-app",
                "software_packageVersion": "1",
            },
            {
                "type": "simplelicensing_LicenseExpression",
                "spdxId": "license",
                "simplelicensing_licenseExpression": "MIT OR Apache-2.0",
            },
            {
                "type": "simplelicensing_SimpleLicensingText",
                "spdxId": "custom",
                "name": "Custom",
                "simplelicensing_licenseText": "Custom terms",
            },
            {"type": "software_Sbom", "spdxId": "sbom", "rootElement": ["package"]},
            {"type": "SpdxDocument", "spdxId": "document", "rootElement": ["sbom"]},
        ]
        for version in ("3.0", "3.0.1"):
            name, components = self.parse(
                {
                    "@graph": graph,
                    "@context": f"https://spdx.org/rdf/{version}/spdx-context.jsonld",
                }
            )
            self.assertEqual(name, "test-app")
            self.assertEqual(
                components, [("test-app", "1", ["Custom", "MIT OR Apache-2.0"])]
            )

    def test_spdx3_missing_license_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unresolved SPDX license"):
            self.parse(
                {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                    "@graph": [
                        {"type": "SpdxDocument", "spdxId": "doc"},
                        {"type": "software_Package", "spdxId": "p", "name": "package"},
                        {
                            "type": "Relationship",
                            "from": "p",
                            "to": ["missing"],
                            "relationshipType": "hasDeclaredLicense",
                        },
                    ],
                }
            )


class StreamingTests(unittest.TestCase):
    def test_nested_components_stream_without_retaining_document(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            # A parent with many children defeats item-based parsers that build the parent.
            with path.open("w") as stream:
                stream.write('{"components":[{"name":"parent","components":[')
                for i in range(15000):
                    if i:
                        stream.write(",")
                    json.dump(
                        {"name": f"lib-{i}", "properties": [{"value": "x" * 100}] * 10},
                        stream,
                    )
                # Metadata after components exercises order-independent format detection.
                stream.write(']}],"metadata":{"component":{"name":"large-app"}},')
                stream.write('"bomFormat":"CycloneDX","specVersion":"1.6"}')
            tracemalloc.start()
            try:
                name, components = parse_sbom(path)
                self.assertIs(iter(components), components)
                self.assertEqual(sum(1 for _ in components), 15001)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(name, "large-app")
            self.assertLess(peak, 4 * 1024 * 1024)

    def test_bom_and_late_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            path.write_text(
                '{"packages":[{"name":"lib"}],"name":"app","spdxVersion":"SPDX-2.3"}',
                encoding="utf-8-sig",
            )
            name, components = parse_sbom(path)
            self.assertEqual((name, list(components)), ("app", [("lib", None, [])]))

    def test_spdx3_graph_index_and_relationship_fanout_stay_on_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large-spdx3.json"
            with path.open("w") as stream:
                stream.write(
                    '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":['
                )
                json.dump(
                    {"type": "SpdxDocument", "spdxId": "doc", "name": "large"}, stream
                )
                for i in range(5000):
                    stream.write(",")
                    json.dump(
                        {
                            "type": "software_Package",
                            "spdxId": f"package-{i}",
                            "name": f"lib-{i}",
                        },
                        stream,
                    )
                stream.write(',{"type":"Relationship","from":"doc","to":[')
                for i in range(30000):
                    if i:
                        stream.write(",")
                    json.dump(f"package-{i}", stream)
                # Relationship type follows the huge fan-out; it must not accumulate.
                stream.write('],"relationshipType":"contains"}]}')
            tracemalloc.start()
            try:
                name, components = parse_sbom(path)
                self.assertEqual(sum(1 for _ in components), 5000)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertEqual(name, "large")
            self.assertLess(peak, 4 * 1024 * 1024)

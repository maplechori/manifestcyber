"""Shared backend behavior. PostgreSQL tests require a disposable test database."""

import os
import unittest

from database import DatabaseError, documents, open_database


class DatabaseContract:
    def test_catalog_lists_and_literal_partial_matching(self):
        self.db.initialize()
        self.assertEqual(self.db.list_components(), [])
        self.assertEqual(self.db.list_licenses(), [])
        self.db.replace_document(
            "one",
            "app-one",
            [
                ("Requests", "1", ["MIT"]),
                ("Requests", "1", ["MIT"]),
                ("percent%_lib", None, []),
            ],
        )
        self.db.replace_document(
            "two", "app-two", [("requests-extra", "2", ["Apache-2.0", "MIT"])]
        )
        self.assertEqual(len(self.db.query(component="QUEST")), 2)
        self.assertEqual(
            self.db.query(component="quest", version="1"),
            [
                {
                    "component": "Requests",
                    "version": "1",
                    "document": "app-one",
                    "source": "one",
                }
            ],
        )
        self.assertEqual(
            self.db.query(component="%_"),
            [
                {
                    "component": "percent%_lib",
                    "version": None,
                    "document": "app-one",
                    "source": "one",
                }
            ],
        )
        self.assertEqual(self.db.query(component="' OR 1=1 --"), [])
        self.assertEqual(self.db.query(license_value="mit"), [])
        rows = self.db.list_components()
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            next(
                row["licenses"] for row in rows if row["component"] == "requests-extra"
            ),
            ["Apache-2.0", "MIT"],
        )
        self.assertEqual(
            next(row["licenses"] for row in rows if row["component"] == "percent%_lib"),
            [],
        )
        self.assertEqual(
            set(rows[0]), {"component", "version", "licenses", "document", "source"}
        )
        self.assertTrue(
            any(
                row["component"] == "percent%_lib" and row["version"] is None
                for row in rows
            )
        )
        self.assertEqual(self.db.list_licenses(), ["Apache-2.0", "MIT"])
        rows = self.db.query(license_value="MIT")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["license"] == "MIT" for row in rows))
        self.assertEqual(
            set(rows[0]), {"component", "version", "license", "document", "source"}
        )
        self.db.replace_document("two", "app-two", [])
        self.assertEqual(self.db.list_licenses(), ["MIT"])
        self.assertEqual(len(self.db.list_components()), 2)

    def test_component_query_keeps_matching_versions_in_one_document(self):
        self.db.initialize()
        self.db.replace_document(
            "source",
            "app",
            [
                ("requests", "1", []),
                ("requests", "2", []),
                ("requests-extra", None, []),
                ("requests", "1", []),
            ],
        )
        rows = self.db.query(component="request")
        self.assertEqual(
            [(row["component"], row["version"]) for row in rows],
            [("requests", "1"), ("requests", "2"), ("requests-extra", None)],
        )
        self.assertEqual(len(self.db.query(component="request", version="2")), 1)

    def test_lazy_parse_failure_rolls_back(self):
        self.db.initialize()
        self.db.replace_document("test-source", "original", [("original", "1", [])])

        def failing_components():
            yield "partial", "2", []
            raise ValueError("invalid later component")

        with self.assertRaises(ValueError):
            self.db.replace_document("test-source", "replacement", failing_components())
        self.assertEqual(self.db.query(component="partial"), [])
        self.assertEqual(self.db.query(component="original")[0]["document"], "original")

    def test_replacement_queries_and_rollback(self):
        self.db.initialize()
        self.db.replace_document("test-source", "app", [("lib", "1", ["MIT"])])
        self.assertEqual(
            self.db.query(component="lib", version="1"),
            [
                {
                    "component": "lib",
                    "version": "1",
                    "document": "app",
                    "source": "test-source",
                }
            ],
        )
        self.assertEqual(self.db.query(component="lib", version="2"), [])
        self.assertEqual(self.db.query(license_value="MIT")[0]["component"], "lib")
        # A failure after the delete must roll back the entire replacement.
        with self.assertRaises(DatabaseError):
            self.db.replace_document("test-source", "app", [(None, "2", [])])
        self.assertEqual(len(self.db.query(component="lib", version="1")), 1)
        self.db.initialize()
        self.assertEqual(len(self.db.query(component="lib")), 1)
        self.db.replace_document("test-source", "app", [("new", None, [])])
        self.assertEqual(self.db.query(license_value="MIT"), [])
        self.assertEqual(self.db.query(component="lib"), [])


@unittest.skipUnless(
    os.environ.get("SBOM_TEST_POSTGRES"),
    "set SBOM_TEST_POSTGRES to a disposable PostgreSQL database URL",
)
class PostgreSQLTests(DatabaseContract, unittest.TestCase):
    def setUp(self):
        self.db = open_database(os.environ["SBOM_TEST_POSTGRES"])
        self.addCleanup(self.db.close)
        self.db.initialize()
        # Only use a disposable test database; this suite clears its documents.
        with self.db.transaction() as connection:
            connection.execute(documents.delete())

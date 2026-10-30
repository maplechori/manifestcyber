"""Integration helpers. SBOM_TEST_POSTGRES must reference a disposable database."""

import os
import threading

from werkzeug.serving import make_server

from api import create_app
from database import documents, open_database


def test_app(test):
    url = os.environ.get("SBOM_TEST_POSTGRES")
    if not url:
        test.skipTest("set SBOM_TEST_POSTGRES to a disposable PostgreSQL database URL")
    db = open_database(url)
    try:
        db.initialize()
        with db.transaction() as connection:
            connection.execute(documents.delete())
    finally:
        db.close()
    return create_app({"TESTING": True, "SBOM_DATABASE": url})


def serve(test, app):
    server = make_server("127.0.0.1", 0, app)
    test.addCleanup(server.server_close)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    test.addCleanup(thread.join, 5)
    test.addCleanup(server.shutdown)
    return f"http://127.0.0.1:{server.server_port}"

"""Flask API for streamed SBOM ingestion and database queries."""

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import click
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from database import DatabaseError, open_database
from service import ingest, validate_query


def create_app(config=None):
    app = Flask(__name__)
    app.config["SBOM_DATABASE"] = os.environ.get(
        "SBOM_DATABASE", "postgresql://sbom:sbom@localhost:5432/sbom"
    )
    if config:
        app.config.update(config)

    @contextmanager
    def database():
        db = open_database(app.config["SBOM_DATABASE"])
        try:
            yield db
        finally:
            db.close()

    @app.cli.command("init-db")
    def init_db():
        """Create missing PostgreSQL tables without deleting existing data."""
        with database() as db:
            db.initialize()
        click.echo("Database initialized.")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.post("/ingest")
    def ingest_document():
        if request.mimetype != "application/json":
            return jsonify(
                error="send the SBOM as an application/json request body"
            ), 415
        source = request.args.get("source", "")
        filename = request.args.get("filename", "sbom.json")
        if not source.strip():
            raise ValueError("source is required to identify the document")
        if not filename or Path(filename).name != filename or filename in (".", ".."):
            raise ValueError("filename must be a plain filename")
        # The two-pass parser needs a seekable file. Never load request.data/get_json().
        with tempfile.TemporaryDirectory(prefix="sbom-upload-") as directory:
            path = Path(directory) / filename
            with path.open("wb") as stream:
                shutil.copyfileobj(request.stream, stream, length=64 * 1024)
            with database() as db:
                return jsonify(ingest(db, path, source))

    @app.get("/query")
    def query_documents():
        allowed = {"component", "version", "license"}
        if any(
            key not in allowed or len(request.args.getlist(key)) != 1
            for key in request.args
        ):
            raise ValueError("unknown or repeated query parameter")
        component = request.args.get("component")
        version = request.args.get("version")
        license_value = request.args.get("license")
        validate_query(component, version, license_value)
        with database() as db:
            return jsonify(db.query(component, version, license_value))

    @app.get("/components")
    def list_components():
        if request.args:
            raise ValueError("component listing does not accept query parameters")
        with database() as db:
            return jsonify(db.list_components())

    @app.get("/licenses")
    def list_licenses():
        if request.args:
            raise ValueError("license listing does not accept query parameters")
        with database() as db:
            return jsonify(db.list_licenses())

    @app.errorhandler(ValueError)
    @app.errorhandler(RecursionError)
    def invalid_input(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(DatabaseError)
    def database_error(error):
        app.logger.error("Database operation failed: %s", error)
        return jsonify(
            error="database operation failed; check server configuration and initialization"
        ), 503

    @app.errorhandler(OSError)
    def storage_error(error):
        app.logger.error("Upload storage failed: %s", error)
        return jsonify(error="upload storage failed"), 500

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    return app

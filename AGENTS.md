# Repository Guidelines

## Project Context

This repository is a take-home test for Manifest Cyber, whose product focuses on software supply chain security using software bills of materials (SBOMs). Keep changes aligned with assignment requirements. Prefer clear, reviewable code and document assumptions rather than adding production infrastructure beyond the exercise's scope.

## Project Structure & Module Organization

The Python 3.10+ CLI communicates exclusively with a Flask API. PostgreSQL is the sole database, accessed by the service through SQLAlchemy Core and Psycopg.

- `sbom_cli.py` handles CLI arguments; `remote.py` streams HTTP uploads.
- `api.py` defines Flask routes and administrative commands; `service.py` contains application operations.
- `parsers.py` streams CycloneDX, Syft, and SPDX JSON using ijson; `spdx3.py` resolves compact SPDX 3 JSON-LD with a temporary disk index.
- `database.py` defines PostgreSQL tables and transactions.
- `examples/` contains sample inputs; `tests/` contains unit and integration tests.

## Build, Test, and Development Commands

- `uv sync`: install the project and locked runtime/development dependencies.
- `uv run pre-commit install`: enable Ruff checks before commits.
- `uv run ruff check .` and `uv run ruff format --check .`: verify lint and formatting.
- `docker compose up -d --build`: start PostgreSQL, initialize its schema, and start the API on localhost:5000.
- `uv run sbom-cli ingest examples/app.json`: upload and ingest the sample.
- `uv run sbom-cli query --component requests --version 2.32.3`: find documents.
- `uv run sbom-cli query --license Apache-2.0`: find licensed components.
- `uv run sbom-cli list-components` and `uv run sbom-cli list-licenses`: inspect stored catalogs.
- `uv run flask --app api:create_app init-db`: initialize the server database explicitly.
- `uv run python -m unittest discover -s tests -v`: run tests.

Use `--endpoint URL` or `SBOM_ENDPOINT` to select the API. Only the service reads `SBOM_DATABASE`, which must be a PostgreSQL URL. Run `uv lock` after dependency changes and commit `uv.lock`.

## Coding Style & Testing Guidelines

Use four-space indentation, snake_case names, and SQLAlchemy expressions. Keep responsibilities in separate functions. Ruff handles linting, import ordering, and formatting with an 88-character width and Python 3.10 target. Pre-commit applies safe lint fixes before formatting; review and stage fixes before committing. No coverage threshold is configured. Never materialize component iterators or entire request bodies during ingestion.

Tests use `unittest` and `test_*.py` filenames. Parser tests run independently. Integration tests require `SBOM_TEST_POSTGRES` pointing to a disposable database and clear its documents. Cover HTTP errors, format detection, memory bounds, catalogs, partial-name searches, replacement, and transaction rollback. Component searches use case-insensitive literal substrings; version and license filters remain exact.

## Commit & Pull Request Guidelines

Use concise, imperative commit subjects. Pull requests should explain the change, purpose, validation, and dependency updates. Keep credentials and local secrets out of commits.

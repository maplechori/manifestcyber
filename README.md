# SBOM CLI

SBOM CLI is a Python command-line tool for uploading software bills of materials to a Flask API backed by PostgreSQL. Once the service is running, use `uv run sbom-cli ingest <file>` to import CycloneDX, Syft, or SPDX JSON, then `uv run sbom-cli query --component <name>` to search by partial component name, optionally adding `--version <version>`. Use `query --license <license>` to find components by license, `list-components` to see components and versions, and `list-licenses` to see available licenses.

The CLI connects to `http://localhost:5000` by default; pass `--endpoint <url>` before the command or set `SBOM_ENDPOINT` to use another service. See [INSTRUCTIONS.md](INSTRUCTIONS.md) for uv installation, service setup, supported formats, API documentation, and development commands.

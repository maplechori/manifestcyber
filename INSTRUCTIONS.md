# SBOM CLI

Manifest Cyber take-home exercise: a Python CLI uploads SBOMs to a Flask API,
which streams their components into PostgreSQL using SQLAlchemy Core. All CLI
operations use HTTP; database connections belong to the service.

```mermaid
flowchart LR
    CLI[Python CLI] -->|HTTP upload / query| API[Flask API]
    API -->|SQLAlchemy + Psycopg| DB[(PostgreSQL)]
    API --> Parser[ijson streaming parser]
```

The same stack can run locally or on a connected server. The CLI only needs its
API endpoint; it never connects to PostgreSQL or creates database tables.

Requires Python 3.10+, [uv](https://docs.astral.sh/uv/getting-started/installation/),
and Docker Compose for the local service.

## Install uv

Install uv using one of the methods below from the
[official installation guide](https://docs.astral.sh/uv/getting-started/installation/).

On macOS or Linux:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Alternatively, if you use Homebrew:

```sh
brew install uv
```

Restart your terminal after installation so the updated PATH takes effect, then
verify that uv is available:

```sh
uv --version
```

Continue with the project setup below. `uv sync` creates the project's `.venv`
and installs dependencies from `uv.lock`.

## Quick start

```sh
uv sync
docker compose up -d --build
docker compose wait postgres-init
curl --fail --retry 10 --retry-connrefused --retry-delay 1 http://localhost:5000/health
uv run sbom-cli ingest examples/app.json
uv run sbom-cli query --component requests
uv run sbom-cli query --component requests --version 2.32.3
uv run sbom-cli query --license Apache-2.0
uv run sbom-cli list-components
uv run sbom-cli list-licenses
```

Compose waits for PostgreSQL to become healthy, runs schema initialization, and
starts Flask. The health request above confirms that the API is accepting HTTP
requests before ingestion. Docker must be running; use `docker compose logs api`
if startup fails.

The CLI defaults to `http://localhost:5000`. Select a different API using
`--endpoint` before the subcommand or the `SBOM_ENDPOINT` environment variable:

```sh
uv run sbom-cli --endpoint https://your-service.example ingest examples/syft.json
SBOM_ENDPOINT=https://your-service.example uv run sbom-cli query --license MIT
```

An explicit `--endpoint` overrides the environment variable. Successful output is
JSON; errors go to stderr with a nonzero exit status. The client streams uploads,
uses a 300-second socket timeout, and does not automatically retry uploads.
Commit `uv.lock` with dependency changes; use `uv lock` to refresh it and
`uv sync --locked` to install without modifying it.

## Supported formats and ingest commands

`ingest` detects the format from JSON contents, regardless of filename or
extension. There is no separate `parse` command or format flag.

| Format | Versions/layout | Detection | Component fields |
| --- | --- | --- | --- |
| CycloneDX JSON | 1.6 | `bomFormat`, `specVersion` | Nested `components`; `name`, `version`, `licenses` |
| Syft native JSON | Native `artifacts` layout | `descriptor.name == "syft"` or Anchore Syft schema URL | `artifacts`; `name`, `version`, `licenses` |
| SPDX JSON | 2.2, 2.3, 2.3.1 | `spdxVersion` | `packages`; `name`, `versionInfo`, `licenseDeclared`, `licenseConcluded` |
| SPDX compact JSON-LD | 3.0, 3.0.1 | Official SPDX `@context` URL and `@graph` | `software_Package`; `software_packageVersion`; declared/concluded license relationships |

```sh
# CycloneDX
uv run sbom-cli ingest examples/app.json
# Syft
uv run sbom-cli ingest examples/syft.json
# SPDX 2
uv run sbom-cli ingest examples/spdx.json
# SPDX 3: the supplied Pitloom sample
uv run sbom-cli ingest examples/pitloom-0.22.0.spdx3.json
uv run sbom-cli query --component pitloom --version 0.22.0
uv run sbom-cli query --license Apache-2.0
```

Syft licenses prefer `spdxExpression`, then `value`. SPDX declared and concluded
licenses are both searchable. Duplicate license values are removed, and
`NONE`/`NOASSERTION` are skipped for Syft and SPDX. The Syft example is a minimal
consumed-field fixture, not a complete schema-valid export.

The Pitloom sample is SPDX 3.0.1 and contains 27 packages, including
`pitloom@0.22.0` under `Apache-2.0`. SPDX 3 ingestion resolves
`hasDeclaredLicense` and `hasConcludedLicense` edges to Simple Licensing expression
or text nodes, regardless of graph order. Missing referenced licenses produce an
error rather than silently dropping license information. All package nodes are
included; files, annotations, and non-license relationships are ignored.

SPDX 3 support is limited to the official compact JSON-LD vocabulary used by the
sample, with string type/reference fields. Arbitrary context aliases, expanded
JSON-LD, multiple document nodes, and other licensing profiles are unsupported.
Contexts are recognized locally and never downloaded. Validation covers consumed
fields, not full schemas. XML, SPDX tag-value, file-level licenses, and
license-expression evaluation are unsupported.
Format references: [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/),
[Syft schemas](https://github.com/anchore/syft/tree/main/schema/json), and
[SPDX 2 package fields](https://spdx.github.io/spdx-spec/v2.3.1/package-information/), and
[SPDX 3 packages](https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/Package/).

## Matching and document identity

Component names match case-insensitive substrings: `--component quest` matches
`requests` and `requests-extra`. `%` and `_` are literal characters, not wildcard
operators. Versions and license values still match exactly and case-sensitively. Whole
license expressions are searchable; `MIT` does not match `MIT OR Apache-2.0`.
Missing versions are null; no query matches produce `[]`. `--component` and
`--license` are mutually exclusive, and `--version` requires `--component`.

Example ingestion output:

```json
{"document": "example-app", "components": 2}
```

Example component-query output (the source path reflects the uploading client):

```json
[{"component": "requests", "version": "2.32.3", "document": "example-app", "source": "/path/to/examples/app.json"}]
```

Component and license queries return `component`, `version`, `document`, and
`source`. Each distinct matched component/version/document/source is a separate
row, so partial-name searches show which components matched and preserve multiple
versions in the same document. License queries additionally include a `license`
field containing the matched stored license value, including whole expressions
or custom license names.

For example, `uv run sbom-cli query --license Apache-2.0` returns:

```json
[{"component": "requests", "version": "2.32.3", "license": "Apache-2.0", "document": "example-app", "source": "/path/to/examples/app.json"}]
```
Document names come from CycloneDX `metadata.component.name`, Syft `source.name`,
or SPDX 2 `name`, falling back to the uploaded filename. SPDX 3 uses the document
name, then follows the first root through SBOM/package nodes to find a name. Nested components are
flattened into the document. CycloneDX's metadata component describes the owner;
its children are included, but it is not its own dependency. Graph edges are ignored.

The CLI sends the absolute client file path as a stable source identity.
Re-ingesting that source atomically replaces its contents. Different clients
using the same path share that identity in this prototype.

## List components and licenses

```sh
uv run sbom-cli list-components
uv run sbom-cli list-licenses
# Both commands also accept the global endpoint option
uv run sbom-cli --endpoint http://localhost:5000 list-components
# Search an incomplete name, optionally restricted to an exact version
uv run sbom-cli query --component loom --version 0.22.0
```

`list-components` returns `component`, `version`, `licenses`, `document`, and `source`
records across all uploaded SBOMs. `licenses` is a sorted, deduplicated array;
components without licenses show `[]`. Missing versions show `null`. Different
versions and owning documents remain separate. Results are sorted by component,
version, document, and source.

`list-licenses` returns a sorted JSON array of distinct stored license values,
for example `["Apache-2.0", "MIT"]`. Whole license expressions and custom names
are included. These are licenses present in uploaded documents, not a global SPDX
license catalog. Empty databases return `[]` for both commands; replacing a
source removes its obsolete entries. Listing results are collected in memory.

## Service configuration and administration

Compose runs PostgreSQL 17, a one-shot `postgres-init` service, and the Flask API.
The API starts after schema initialization and is published on localhost:5000.
Configuration can be supplied through environment variables:

| Variable | Used by | Default | Purpose |
| --- | --- | --- | --- |
| `SBOM_ENDPOINT` | CLI | `http://localhost:5000` | API base URL; overridden by `--endpoint` |
| `SBOM_DATABASE` | Flask service | `postgresql://sbom:sbom@localhost:5432/sbom` | PostgreSQL connection URL |
| `API_PORT` | Compose | `5000` | API port on the host |
| `POSTGRES_DB` | Compose | `sbom` | Database name |
| `POSTGRES_USER` | Compose | `sbom` | Database user |
| `POSTGRES_PASSWORD` | Compose | `sbom` | Local development password |
| `POSTGRES_PORT` | Compose | `5432` | PostgreSQL port on the host |
| `SBOM_TEST_POSTGRES` | Tests | Unset | Disposable integration-test database URL |

Compose reads its variables from the shell or an ignored `.env` file. Its
containers use `SBOM_DATABASE=postgresql://` with PostgreSQL's `PGHOST`, `PGUSER`,
`PGPASSWORD`, and `PGDATABASE` variables to connect internally. Changing a host port
does not change the port used between containers. Data persists in `postgres_data`.

For example, to publish the API on port 8000:

```sh
API_PORT=8000 docker compose up -d
uv run sbom-cli --endpoint http://localhost:8000 query --component requests
```

`docker compose down` keeps the data; `docker compose down -v` deletes it.
Initialization creates missing tables without migrating existing schemas.
Credentials are applied only when the PostgreSQL volume is first initialized.

To run Flask outside Docker against an existing PostgreSQL server:

```sh
export SBOM_DATABASE=postgresql://sbom:sbom@localhost:5432/sbom
uv run flask --app api:create_app init-db
uv run flask --app api:create_app run --host 127.0.0.1 --port 5000
```

Only the service reads `SBOM_DATABASE`; it must be a PostgreSQL URL. Its default
is the local URL above. Schema initialization is a Flask administration command. Run it when setting up
an external PostgreSQL instance, or let Compose's `postgres-init` service run it.
The client exposes `ingest`, `query`, `list-components`, and `list-licenses`; `--db` and client-side `init-db` have
been removed. Existing SQLite data is not migrated automatically.

### HTTP API

| Method | Route | Input | Output |
| --- | --- | --- | --- |
| POST | `/ingest?source=<id>&filename=<name>` | Raw JSON body; `Content-Type: application/json` | Document and component count |
| GET | `/query?component=<name>&version=<version>` | Case-insensitive name substring; version optional and exact | Matched components with versions and owning documents |
| GET | `/query?license=<license>` | Exact license value | Components with versions, matched license, and owning documents |
| GET | `/components` | None | All distinct components with versions and owning documents |
| GET | `/licenses` | None | Sorted distinct license values |
| GET | `/health` | None | `{"status":"ok"}` process liveness |

`source` identifies the upload; it is not a server path to read. `filename`
defaults to `sbom.json` and supplies the document-name fallback.

```sh
curl --fail-with-body -H 'Content-Type: application/json' \
  --data-binary @examples/app.json \
  'http://localhost:5000/ingest?source=example-app&filename=app.json'
curl --get --data-urlencode 'component=requests' \
  --data-urlencode 'version=2.32.3' http://localhost:5000/query
```

Errors use JSON `{"error":"..."}`: invalid input returns 400, unsupported content
type 415, database failures 503, and temporary upload-storage failures 500. Inspect startup with `docker compose logs api`.
This exercise uses Flask's development server without authentication or tenant
isolation. An internet deployment needs a production WSGI server and an
authenticated HTTPS gateway before public exposure.

## Large-file ingestion

Uploads stream to temporary disk in 64 KiB chunks and are deleted afterward.
Server disk must accommodate concurrent uploads and temporary indexes. For
CycloneDX, Syft, and SPDX 2, `ijson` scans each file twice:
once for format/name metadata and JSON validation, then to yield components into
one database transaction. Metadata may appear after the component arrays.

Memory depends on parser buffers, nesting depth, the largest JSON scalar, and a
component's licenses, rather than total component count. Unknown package metadata
and child arrays are never materialized. Parse or insert failures roll back the
replacement. Query results are still collected in memory.

SPDX 3 uses one additional streaming pass and a temporary native `dbm` index to
resolve package/license references without retaining the graph. Large relationship
target arrays are spooled to disk. The index is deleted when parsing finishes or
fails; PostgreSQL remains the only persistent application database. Python must
provide a native dbm backend (gdbm/ndbm); the in-memory-key `dbm.dumb` fallback is
rejected. Root traversal retains its visited IDs, and license memory scales with
the licenses attached to an individual package.

## Linting, formatting, and pre-commit

`uv sync` installs Ruff and pre-commit from the locked development dependencies.
Install the Git hook once per checkout:

```sh
uv run pre-commit install
uv run pre-commit run --all-files
```

Before each commit, the hooks apply safe lint fixes and format changed Python
files. Review and stage any fixes, then commit again. Hooks use `uv run --locked`
to share the same Ruff version as manual checks; uv must be on your PATH.

```sh
uv run ruff check .
uv run ruff format --check .
# Apply fixes and formatting
uv run ruff check --fix .
uv run ruff format .
```

Ruff targets Python 3.10, uses an 88-character formatting width, and checks Python
errors, unused imports, and import ordering. Settings live in `pyproject.toml`;
`.pre-commit-config.yaml` runs lint fixes before formatting. Docker installs only
runtime dependencies with `uv sync --locked --no-dev`.

## Structure and tests

`sbom_cli.py` and `remote.py` implement the HTTP client. `api.py` creates the Flask
service; `service.py` contains application operations. `parsers.py` handles
streaming format detection; `spdx3.py` resolves compact JSON-LD references with a
temporary disk index. `database.py` owns PostgreSQL tables and transactions.

```sh
uv run python -m unittest discover -s tests -v
```

Parser tests run without a database. API, CLI, and database integration tests need
a **disposable PostgreSQL database**; they clear its documents before each test:

```sh
docker compose exec postgres createdb -U sbom sbom_test
SBOM_TEST_POSTGRES=postgresql://sbom:sbom@localhost:5432/sbom_test \
  uv run python -m unittest discover -s tests -v
```

Without `SBOM_TEST_POSTGRES`, integration tests are skipped. The suite checks
streaming memory, supported formats, queries, replacement, rollback, and live HTTP
CLI calls. Local socket access is required for HTTP tests.

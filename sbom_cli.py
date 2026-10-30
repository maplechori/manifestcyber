"""Ingest and query JSON SBOMs through the Flask API."""

import argparse
import json
import os
import sys
from pathlib import Path

from remote import RemoteClient
from service import validate_query


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("SBOM_ENDPOINT", "http://localhost:5000"),
        help="API base URL (env: SBOM_ENDPOINT; default: http://localhost:5000)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    ingest_parser = commands.add_parser(
        "ingest", help="ingest CycloneDX, Syft, or SPDX JSON (auto-detected)"
    )
    ingest_parser.add_argument("sbom_file", type=Path)
    query_parser = commands.add_parser(
        "query", help="find documents or licensed components"
    )
    filters = query_parser.add_mutually_exclusive_group(required=True)
    filters.add_argument("--component", help="case-insensitive name substring")
    filters.add_argument("--license", dest="license_value")
    query_parser.add_argument("--version")
    commands.add_parser(
        "list-components", help="list all components with owning documents"
    )
    commands.add_parser("list-licenses", help="list all distinct license values")
    args = parser.parse_args(argv)
    if args.command == "query" and args.version is not None and args.component is None:
        parser.error("--version requires --component")
    try:
        if args.command == "query":
            validate_query(args.component, args.version, args.license_value)
        client = RemoteClient(args.endpoint)
        if args.command == "ingest":
            result = client.ingest(args.sbom_file)
        elif args.command == "query":
            result = client.query(args.component, args.version, args.license_value)
        elif args.command == "list-components":
            result = client.list_components()
        else:
            result = client.list_licenses()
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

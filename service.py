"""Ingestion and query validation for the SBOM service."""

from parsers import parse_sbom


def ingest(db, path, source=None):
    name, components = parse_sbom(path)
    count = db.replace_document(source or str(path.resolve()), name, components)
    return {"document": name, "components": count}


def validate_query(component=None, version=None, license_value=None):
    if (component is None) == (license_value is None):
        raise ValueError("provide exactly one of component or license")
    if version is not None and component is None:
        raise ValueError("version requires component")
    if any(
        value is not None and not value.strip()
        for value in (component, version, license_value)
    ):
        raise ValueError("query values must not be empty")

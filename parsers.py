"""Stream JSON SBOMs: metadata scan followed by lazy component events."""

import re
from contextlib import contextmanager

import ijson
from ijson.common import ObjectBuilder


@contextmanager
def events(path):
    with path.open("rb") as stream:
        if stream.read(3) != b"\xef\xbb\xbf":
            stream.seek(0)
        try:
            yield ijson.parse(stream)
        except ijson.JSONError as exc:
            raise ValueError(f"invalid SBOM JSON: {exc}") from exc


def text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value


def parse_sbom(path):
    # Read only selected scalar metadata, even when format markers follow the packages.
    fields = {
        "bomFormat",
        "specVersion",
        "spdxVersion",
        "descriptor.name",
        "schema.url",
        "source.name",
        "metadata.component.name",
        "name",
        "@context",
        "@context.item",
    }
    values = {}
    shapes = {}
    with events(path) as parser:
        first = next(parser, None)
        if first != ("", "start_map", None):
            raise ValueError("SBOM must be a JSON object")
        for prefix, event, value in parser:
            if prefix in fields and event not in ("end_map", "end_array", "map_key"):
                values[prefix] = value if event == "string" else None
            if prefix in {
                "metadata",
                "metadata.component",
                "source",
                "artifacts",
                "packages",
                "@graph",
            }:
                if event not in ("end_map", "end_array", "map_key"):
                    shapes[prefix] = event
    if "bomFormat" in values:
        if values["bomFormat"] != "CycloneDX" or values.get("specVersion") != "1.6":
            raise ValueError("supported CycloneDX version: 1.6")
        for key in ("metadata", "metadata.component"):
            if key in shapes and shapes[key] != "start_map":
                raise ValueError(f"{key} must be an object")
        kind, name_key = "cyclonedx", "metadata.component.name"
    elif any(
        values.get(key)
        in {
            "https://spdx.org/rdf/3.0/spdx-context.jsonld",
            "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        }
        for key in ("@context", "@context.item")
    ):
        if shapes.get("@graph") != "start_array":
            raise ValueError("SPDX 3 JSON-LD needs an @graph array")
        from spdx3 import parse_spdx3

        return parse_spdx3(path)
    elif "spdxVersion" in values:
        if values["spdxVersion"] not in ("SPDX-2.2", "SPDX-2.3", "SPDX-2.3.1"):
            raise ValueError(
                "supported SPDX 2 JSON versions: 2.2, 2.3, 2.3.1; SPDX 3 requires compact JSON-LD"
            )
        if "packages" in shapes and shapes["packages"] != "start_array":
            raise ValueError("packages must be an array")
        kind, name_key = "spdx", "name"
    elif values.get("descriptor.name") == "syft" or (
        isinstance(values.get("schema.url"), str)
        and values["schema.url"].startswith(
            "https://raw.githubusercontent.com/anchore/syft/"
        )
    ):
        if shapes.get("artifacts") != "start_array":
            raise ValueError("Syft JSON needs an artifacts array")
        if "source" in shapes and shapes["source"] != "start_map":
            raise ValueError("source must be an object")
        kind, name_key = "syft", "source.name"
    else:
        raise ValueError(
            "unrecognized SBOM format; expected CycloneDX 1.6, Syft JSON, SPDX 2 JSON, or SPDX 3 compact JSON-LD"
        )
    name = text(values.get(name_key, path.name), "document name")
    return name, stream_components(path, kind)


CDX_COMPONENT = re.compile(
    r"(?:metadata\.component\.)?components\.item(?:\.components\.item)*\Z"
)
CDX_ARRAY = re.compile(r"(?:metadata\.component\.)?components(?:\.item\.components)*\Z")


def stream_components(path, kind):
    """Retain consumed fields only; never construct a package's metadata/children."""
    stack = []
    builder = None
    license_depth = 0
    with events(path) as parser:
        for prefix, event, value in parser:
            if builder is not None:
                builder.event(event, value)
                if event in ("start_map", "start_array"):
                    license_depth += 1
                elif event in ("end_map", "end_array"):
                    license_depth -= 1
                if license_depth == 0:
                    stack[-1][1]["licenses"] = builder.value
                    builder = None
                continue
            is_record = (
                bool(CDX_COMPONENT.fullmatch(prefix))
                if kind == "cyclonedx"
                else prefix == ("artifacts.item" if kind == "syft" else "packages.item")
            )
            is_array = (
                bool(CDX_ARRAY.fullmatch(prefix))
                if kind == "cyclonedx"
                else prefix == ("artifacts" if kind == "syft" else "packages")
            )
            if is_array and event not in ("start_array", "end_array", "map_key"):
                raise ValueError("components/packages must be an array")
            if is_record:
                if event == "start_map":
                    stack.append((prefix, {}))
                elif event == "end_map":
                    _, record = stack.pop()
                    yield normalize(record, kind)
                elif event != "map_key":
                    raise ValueError("each component must be an object")
            elif stack:
                base, record = stack[-1]
                key = prefix[len(base) + 1 :] if prefix.startswith(base + ".") else ""
                if key in (
                    "name",
                    "version",
                    "versionInfo",
                    "licenseDeclared",
                    "licenseConcluded",
                ):
                    if event not in ("end_map", "end_array", "map_key"):
                        record[key] = (
                            value if event not in ("start_map", "start_array") else []
                        )
                elif key == "licenses":
                    if event == "start_array":
                        builder = ObjectBuilder()
                        builder.event(event, value)
                        license_depth = 1
                    elif event != "map_key":
                        if kind != "syft" or event != "null":
                            raise ValueError("licenses must be an array")


def normalize(record, kind):
    name = text(record.get("name"), "component name")
    version = record.get("versionInfo" if kind == "spdx" else "version")
    if version is not None and not isinstance(version, str):
        raise ValueError("component version must be a string")
    licenses = set()
    if kind == "spdx":
        for key in ("licenseDeclared", "licenseConcluded"):
            if key in record:
                value = text(record[key], key)
                if value not in ("NONE", "NOASSERTION"):
                    licenses.add(value)
    else:
        for entry in record.get("licenses", []):
            if not isinstance(entry, dict):
                raise ValueError("each license entry must be an object")
            if kind == "syft":
                value = entry.get("spdxExpression") or entry.get("value")
            elif "expression" in entry:
                value = entry["expression"]
            else:
                data = entry.get("license")
                if not isinstance(data, dict):
                    raise ValueError("license entry needs a license or expression")
                value = data.get("id") or data.get("name")
            value = text(value, "license value")
            if kind != "syft" or value not in ("NONE", "NOASSERTION"):
                licenses.add(value)
    return name, version, sorted(licenses)

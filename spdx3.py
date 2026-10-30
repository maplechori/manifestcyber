"""Read compact SPDX 3 JSON-LD graphs with a temporary disk-backed ID index."""

import dbm
import json
import tempfile
from contextlib import ExitStack
from pathlib import Path

from parsers import events, text

# Only retain consumed fields; large annotations and file metadata are skipped.
SCALARS = {
    "type",
    "spdxId",
    "@id",
    "name",
    "software_packageVersion",
    "from",
    "relationshipType",
    "simplelicensing_licenseExpression",
    "simplelicensing_licenseText",
    "specVersion",
}
ARRAYS = {"rootElement", "to"}


def graph_nodes(path):
    node = None
    # Relationship fan-outs can be enormous, even for ignored "contains" edges.
    # Spool targets instead of retaining that array; only the first root is needed.
    with ExitStack() as resources, events(path) as parser:
        for prefix, event, value in parser:
            if prefix == "@graph" and event not in (
                "start_array",
                "end_array",
                "map_key",
            ):
                raise ValueError("SPDX @graph must be an array")
            if prefix == "@graph.item":
                if event == "start_map":
                    node = {}
                elif event == "end_map":
                    yield node
                    resources.close()
                    node = None
                elif event != "map_key":
                    raise ValueError("SPDX graph nodes must be objects")
            elif node is not None and prefix.startswith("@graph.item."):
                key = prefix[len("@graph.item.") :]
                if key in SCALARS and event not in ("map_key", "end_map", "end_array"):
                    node[key] = value if event == "string" else None
                elif key in ARRAYS and event not in ("map_key", "end_array"):
                    if event != "start_array":
                        raise ValueError(f"SPDX {key} must be an array of references")
                    if key == "to":
                        node["_targets"] = resources.enter_context(
                            tempfile.TemporaryFile(mode="w+t")
                        )
                    else:
                        node[key] = []
                elif key in {"rootElement.item", "to.item"}:
                    if event == "string":
                        if key == "to.item":
                            node["_targets"].write(json.dumps(value) + "\n")
                        elif not node["rootElement"]:
                            node["rootElement"].append(value)
                    elif event not in ("map_key", "end_map", "end_array"):
                        raise ValueError("SPDX references must be strings")


def get(index, key, default=None):
    value = index.get(key.encode())
    return json.loads(value) if value is not None else default


def put(index, key, value):
    index[key.encode()] = json.dumps(value).encode()


def document_name(index, document, fallback):
    # Follow Document -> SBOM -> root Package, without collecting the graph.
    node = document
    seen = set()
    while node:
        if node.get("name"):
            return text(node["name"], "document name")
        roots = node.get("rootElement", [])
        if not roots:
            break
        root = roots[0]
        if root in seen:
            raise ValueError("cyclic SPDX rootElement references")
        seen.add(root)
        node = get(index, "node:" + root)
    return fallback


def license_value(index, reference):
    node = get(index, "node:" + reference)
    if node is not None:
        if node.get("type") == "simplelicensing_LicenseExpression":
            return text(
                node.get("simplelicensing_licenseExpression"), "license expression"
            )
        if node.get("type") == "simplelicensing_SimpleLicensingText":
            return text(
                node.get("name") or node.get("simplelicensing_licenseText"),
                "license text",
            )
        raise ValueError(f"unsupported SPDX license node: {reference}")
    if reference in {
        f"https://spdx.org/rdf/{version}/terms/Core/{special}"
        for version in ("3.0", "3.0.1")
        for special in ("NoneElement", "NoAssertionElement")
    }:
        return None
    for prefix in ("https://spdx.org/licenses/", "http://spdx.org/licenses/"):
        if reference.startswith(prefix):
            return text(reference[len(prefix) :], "license identifier")
    raise ValueError(f"unresolved SPDX license reference: {reference}")


def parse_spdx3(path):
    temporary = tempfile.TemporaryDirectory(prefix="sbom-spdx3-")
    index_path = str(Path(temporary.name) / "references")
    try:
        with dbm.open(index_path, "n") as index:
            # dbm.dumb keeps all keys in memory; require a native disk-backed backend.
            if index.__class__.__module__ == "dbm.dumb":
                raise ValueError(
                    "SPDX 3 streaming requires Python's native dbm backend"
                )
            document = None
            for node in graph_nodes(path):
                kind = node.get("type")
                if kind == "CreationInfo" and node.get("specVersion") not in (
                    "3.0",
                    "3.0.1",
                ):
                    raise ValueError("supported SPDX JSON-LD versions: 3.0 and 3.0.1")
                if kind in ("Relationship", "LifecycleScopedRelationship"):
                    if node.get("relationshipType") in (
                        "hasDeclaredLicense",
                        "hasConcludedLicense",
                    ):
                        source = text(node.get("from"), "license relationship source")
                        targets = node.get("_targets")
                        if targets is None or targets.tell() == 0:
                            raise ValueError(
                                "license relationship needs target references"
                            )
                        targets.seek(0)
                        key = "licenses:" + source
                        values = get(index, key, [])
                        for target in targets:
                            values.append(json.loads(target))
                        put(index, key, values)
                elif kind in (
                    "software_Package",
                    "SpdxDocument",
                    "software_Sbom",
                    "simplelicensing_LicenseExpression",
                    "simplelicensing_SimpleLicensingText",
                ):
                    identifier = text(
                        node.get("spdxId") or node.get("@id"), "SPDX identifier"
                    )
                    if get(index, "node:" + identifier) is not None:
                        raise ValueError(f"duplicate SPDX identifier: {identifier}")
                    node.pop("_targets", None)
                    put(index, "node:" + identifier, node)
                    if kind == "SpdxDocument":
                        if document is not None:
                            raise ValueError("expected one SPDX document per upload")
                        document = node
            if document is None:
                raise ValueError("SPDX 3 graph needs a SpdxDocument node")
            name = document_name(index, document, path.name)
    except BaseException:
        temporary.cleanup()
        raise

    def components():
        # Close/delete the temporary index even after a lazy parse or database failure.
        with temporary, dbm.open(index_path, "r") as index:
            for node in graph_nodes(path):
                if node.get("type") != "software_Package":
                    continue
                identifier = node.get("spdxId") or node.get("@id")
                licenses = set()
                for reference in get(index, "licenses:" + identifier, []):
                    value = license_value(index, reference)
                    if value is not None and value not in ("NONE", "NOASSERTION"):
                        licenses.add(value)
                version = node.get("software_packageVersion")
                if version is None and "software_packageVersion" in node:
                    raise ValueError("component version must be a string")
                yield (
                    text(node.get("name"), "component name"),
                    version,
                    sorted(licenses),
                )

    return name, components()

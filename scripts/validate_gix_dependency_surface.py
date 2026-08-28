#!/usr/bin/env python3
"""Fail closed if the T037 gix dependency surface gains unqualified authority."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_GIX_VERSION = "0.87.1"
EXPECTED_GIX_FEATURES = {"index", "revision", "sha1"}
FORBIDDEN_GIX_FEATURES = {
    "attributes",
    "async-network-client",
    "async-network-client-async-std",
    "basic",
    "blob-diff",
    "blocking-http-transport-curl",
    "blocking-http-transport-reqwest",
    "blocking-network-client",
    "command",
    "comfort",
    "credentials",
    "default",
    "dirwalk",
    "excludes",
    "extras",
    "mailmap",
    "merge",
    "status",
    "submodule",
    "worktree-archive",
    "worktree-mutation",
    "worktree-stream",
}
FORBIDDEN_PACKAGES = {
    "gix-credentials",
    "gix-ignore",
    "gix-pathspec",
    "gix-prompt",
    "gix-status",
    "gix-submodule",
}
FORBIDDEN_PROTOCOL_FEATURES = {
    "async-client",
    "blocking-client",
}
FORBIDDEN_TRANSPORT_FEATURES = {
    "async-std",
    "blocking-client",
    "curl",
    "http-client-curl",
    "http-client-reqwest",
    "reqwest",
}


def fail(message: str) -> None:
    print(f"gix-dependency-surface: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_metadata(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read cargo metadata: {error}")


def package_name_by_id(metadata: dict[str, Any]) -> dict[str, str]:
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("cargo metadata packages field is missing or malformed")
    result: dict[str, str] = {}
    for package in packages:
        package_id = package.get("id")
        name = package.get("name")
        if isinstance(package_id, str) and isinstance(name, str):
            result[package_id] = name
    return result


def resolved_nodes(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        fail("cargo metadata resolve field is missing")
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list):
        fail("cargo metadata resolve.nodes field is missing")
    return nodes


def single_node(metadata: dict[str, Any], package_name: str) -> dict[str, Any]:
    names = package_name_by_id(metadata)
    matches = [node for node in resolved_nodes(metadata) if names.get(node.get("id")) == package_name]
    if len(matches) != 1:
        fail(f"expected exactly one resolved {package_name!r} node, found {len(matches)}")
    return matches[0]


def require_gix_identity(metadata: dict[str, Any]) -> None:
    packages = metadata.get("packages", [])
    matches = [package for package in packages if package.get("name") == "gix"]
    if len(matches) != 1:
        fail(f"expected exactly one gix package, found {len(matches)}")
    package = matches[0]
    if package.get("version") != EXPECTED_GIX_VERSION:
        fail(f"gix version drifted: expected {EXPECTED_GIX_VERSION}, got {package.get('version')}")
    if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
        fail("gix source is not canonical crates.io")


def require_selected_features(metadata: dict[str, Any]) -> None:
    gix_node = single_node(metadata, "gix")
    selected = set(gix_node.get("features") or [])
    if selected != EXPECTED_GIX_FEATURES:
        fail(f"gix selected features drifted: expected {sorted(EXPECTED_GIX_FEATURES)}, got {sorted(selected)}")
    forbidden = selected & FORBIDDEN_GIX_FEATURES
    if forbidden:
        fail(f"gix forbidden capability features are enabled: {sorted(forbidden)}")

    protocol_features = set(single_node(metadata, "gix-protocol").get("features") or [])
    forbidden_protocol = protocol_features & FORBIDDEN_PROTOCOL_FEATURES
    if forbidden_protocol:
        fail(f"gix-protocol network client features are enabled: {sorted(forbidden_protocol)}")

    transport_features = set(single_node(metadata, "gix-transport").get("features") or [])
    forbidden_transport = transport_features & FORBIDDEN_TRANSPORT_FEATURES
    if forbidden_transport:
        fail(f"gix-transport network features are enabled: {sorted(forbidden_transport)}")


def require_forbidden_packages_absent(metadata: dict[str, Any]) -> None:
    present = set(package_name_by_id(metadata).values())
    unexpected = present & FORBIDDEN_PACKAGES
    if unexpected:
        fail(f"forbidden gix capability packages entered the lock closure: {sorted(unexpected)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args()

    metadata = load_metadata(args.metadata)
    require_gix_identity(metadata)
    require_selected_features(metadata)
    require_forbidden_packages_absent(metadata)
    print("gix-dependency-surface: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

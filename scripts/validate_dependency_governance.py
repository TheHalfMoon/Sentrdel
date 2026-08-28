#!/usr/bin/env python3
"""Fail closed when the trusted Sentrdel dependency graph escapes its declarations."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

CRATES_IO_CARGO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CRATES_IO_DENY_REGISTRY = "https://github.com/rust-lang/crates.io-index"
REQUIRED_DENY_LICENSES = {"Apache-2.0", "MIT", "Unicode-3.0", "BSD-3-Clause", "ISC", "Zlib"}
PRIVILEGED_SURFACES = {"build-script", "proc-macro", "native-link"}


def fail(message: str) -> None:
    print(f"dependency-governance: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def require_exact_workspace_versions(root: Path) -> None:
    cargo = load_toml(root / "Cargo.toml")
    dependencies = cargo.get("workspace", {}).get("dependencies", {})
    if not isinstance(dependencies, dict):
        fail("[workspace.dependencies] is missing or malformed")

    for name, value in sorted(dependencies.items()):
        if isinstance(value, str):
            version = value
            path = None
        elif isinstance(value, dict):
            version = value.get("version")
            path = value.get("path")
        else:
            fail(f"workspace dependency {name!r} has unsupported declaration shape")

        if path is not None and version is None:
            continue
        if not isinstance(version, str) or not version.startswith("="):
            fail(f"workspace dependency {name!r} must use an exact '=version' requirement")
        if any(token in version for token in ("*", ">", "<", "~", "^", ",")):
            fail(f"workspace dependency {name!r} uses a non-exact version requirement: {version}")


def require_locked_sources(root: Path) -> None:
    lock = load_toml(root / "Cargo.lock")
    packages = lock.get("package", [])
    if not isinstance(packages, list):
        fail("Cargo.lock package table is malformed")

    for package in packages:
        source = package.get("source")
        if source is not None and source != CRATES_IO_CARGO_SOURCE:
            fail(
                f"Cargo.lock package {package.get('name')} {package.get('version')} uses "
                f"unqualified source {source!r}"
            )


def require_deny_policy(root: Path) -> None:
    deny = load_toml(root / "deny.toml")
    sources = deny.get("sources", {})
    if sources.get("unknown-registry") != "deny":
        fail("deny.toml must deny unknown registries")
    if sources.get("unknown-git") != "deny":
        fail("deny.toml must deny unknown Git sources")
    if sources.get("allow-registry") != [CRATES_IO_DENY_REGISTRY]:
        fail("deny.toml must allow only the canonical crates.io registry source")

    bans = deny.get("bans", {})
    if bans.get("wildcards") != "deny":
        fail("deny.toml must deny wildcard dependency requirements")

    advisories = deny.get("advisories", {})
    if "vulnerability" in advisories:
        fail("deny.toml must not use removed cargo-deny advisory key 'vulnerability'")
    if advisories.get("yanked") != "deny":
        fail("deny.toml must deny yanked dependency versions")
    if advisories.get("ignore", []) != []:
        fail("deny.toml advisory ignores require explicit later-task governance; T091 admits none")
    if advisories.get("unmaintained", "all") == "none":
        fail("deny.toml must not disable unmaintained-advisory enforcement")
    if advisories.get("unsound", "workspace") == "none":
        fail("deny.toml must not disable unsound-advisory enforcement")

    licenses = deny.get("licenses", {})
    allowed = set(licenses.get("allow", []))
    if not REQUIRED_DENY_LICENSES.issubset(allowed):
        fail("deny.toml license allowlist lost a repository-approved license")


def observed_privileged_surfaces(metadata: dict[str, Any]) -> tuple[dict[tuple[str, str], set[str]], set[tuple[str, str]]]:
    workspace_members = set(metadata.get("workspace_members", []))
    observed: dict[tuple[str, str], set[str]] = defaultdict(set)
    third_party: set[tuple[str, str]] = set()

    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("cargo metadata packages field is missing or malformed")

    for package in packages:
        package_id = package.get("id")
        if package_id in workspace_members:
            continue

        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if not isinstance(name, str) or not isinstance(version, str):
            fail("cargo metadata contains a package without string name/version")
        if source != CRATES_IO_CARGO_SOURCE:
            fail(f"third-party package {name} {version} is not sourced from canonical crates.io")

        key = (name, version)
        third_party.add(key)
        for target in package.get("targets", []):
            kinds = target.get("kind", [])
            if "custom-build" in kinds:
                observed[key].add("build-script")
            if "proc-macro" in kinds:
                observed[key].add("proc-macro")
        if package.get("links"):
            observed[key].add("native-link")

    return observed, third_party


def require_privileged_declarations(root: Path, metadata: dict[str, Any]) -> None:
    declarations_data = load_toml(root / "docs/security/privileged-dependencies.toml")
    declarations = declarations_data.get("package", [])
    if not isinstance(declarations, list):
        fail("privileged-dependencies.toml must contain [[package]] records")

    observed, third_party = observed_privileged_surfaces(metadata)
    declared: dict[tuple[str, str], set[str]] = {}
    qualification_refs: dict[tuple[str, str], str] = {}

    for record in declarations:
        name = record.get("name")
        version = record.get("version")
        surfaces = record.get("surfaces")
        rationale = record.get("rationale")
        owner = record.get("owner")
        qualification = record.get("qualification")

        if not all(isinstance(value, str) and value.strip() for value in (name, version, rationale, owner, qualification)):
            fail("every privileged dependency declaration needs name/version/rationale/owner/qualification")
        if not isinstance(surfaces, list) or not surfaces:
            fail(f"privileged dependency {name} {version} must declare at least one surface")
        surface_set = set(surfaces)
        if not surface_set.issubset(PRIVILEGED_SURFACES):
            fail(f"privileged dependency {name} {version} declares unknown surfaces {sorted(surface_set - PRIVILEGED_SURFACES)}")

        key = (name, version)
        if key in declared:
            fail(f"duplicate privileged dependency declaration for {name} {version}")
        if key not in third_party:
            fail(f"privileged declaration {name} {version} is not present in locked cargo metadata")
        declared[key] = surface_set
        qualification_refs[key] = qualification

    missing_records = sorted(set(observed) - set(declared))
    if missing_records:
        rendered = ", ".join(f"{name} {version}: {sorted(observed[(name, version)])}" for name, version in missing_records)
        fail(f"privileged dependency surface is undeclared: {rendered}")

    for key, surfaces in sorted(observed.items()):
        missing_surfaces = surfaces - declared[key]
        if missing_surfaces:
            fail(f"privileged dependency {key[0]} {key[1]} is missing surfaces {sorted(missing_surfaces)}")

    qualification_text = "\n".join(
        [
            (root / "docs/third-party/source-qualification-ledger.md").read_text(encoding="utf-8"),
            (root / "docs/third-party/t091-self-security-tool-qualification.md").read_text(encoding="utf-8"),
        ]
    )
    for key, qualification in qualification_refs.items():
        if qualification not in qualification_text:
            fail(f"privileged dependency {key[0]} {key[1]} references missing qualification {qualification}")

    print(
        "dependency-governance: privileged surface declarations complete: "
        f"{len(observed)} observed privileged packages / {len(declared)} declarations"
    )


def require_ci_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/self-security.yml").read_text(encoding="utf-8")
    forbidden = ["workflow_dispatch:", "${{ inputs.", "working-directory:", "repository:"]
    for token in forbidden:
        if token in workflow:
            fail(f"self-security workflow contains forbidden target-redirection token {token!r}")

    for required in [
        "permissions:\n  contents: read",
        "persist-credentials: false",
        "cargo +1.98.0 metadata --locked",
        "cargo +1.98.0 audit --file Cargo.lock",
        "cargo +1.98.0 deny check advisories bans licenses sources",
        "scripts/validate_dependency_governance.py",
    ]:
        if required not in workflow:
            fail(f"self-security workflow lost required boundary/gate text {required!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read cargo metadata: {error}")

    require_exact_workspace_versions(root)
    require_locked_sources(root)
    require_deny_policy(root)
    require_ci_boundary(root)
    require_privileged_declarations(root, metadata)
    print("dependency-governance: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Release-grade fail-closed checks for Sentrdel's trusted dependency boundary."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXPECTED_RUST = "1.98.0"
EXPECTED_LOCK_VERSION = 4
RUSTSEC_ADVISORY = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")


def fail(message: str) -> None:
    print(f"release-dependency-policy: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read TOML {path}: {error}")


def require_exact_toolchain(root: Path) -> None:
    toolchain = load_toml(root / "rust-toolchain.toml").get("toolchain", {})
    if toolchain.get("channel") != EXPECTED_RUST:
        fail(f"rust-toolchain.toml must pin Rust exactly to {EXPECTED_RUST}")
    if toolchain.get("profile") != "minimal":
        fail("rust-toolchain.toml must retain the minimal profile")
    components = toolchain.get("components")
    if not isinstance(components, list) or set(components) != {"clippy", "rustfmt"}:
        fail("rust-toolchain.toml must retain exactly clippy and rustfmt components")


def require_lockfile_shape(root: Path) -> None:
    lock = load_toml(root / "Cargo.lock")
    if lock.get("version") != EXPECTED_LOCK_VERSION:
        fail(f"Cargo.lock must use lockfile format version {EXPECTED_LOCK_VERSION}")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        fail("Cargo.lock must contain a non-empty package set")
    for package in packages:
        if not isinstance(package, dict):
            fail("Cargo.lock contains a malformed package record")
        if not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
            fail("Cargo.lock package records require string name/version")


def load_malicious_denylist(root: Path) -> dict[str, str]:
    data = load_toml(root / "docs/security/malicious-package-denylist.toml")
    records = data.get("package")
    if not isinstance(records, list) or not records:
        fail("malicious-package denylist must contain [[package]] records")

    denylist: dict[str, str] = {}
    advisory_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            fail("malicious-package denylist contains a malformed record")
        name = record.get("name")
        advisory = record.get("advisory")
        source = record.get("source")
        reason = record.get("reason")
        if not all(isinstance(value, str) and value.strip() for value in (name, advisory, source, reason)):
            fail("every malicious-package record requires name/advisory/source/reason")
        if name in denylist:
            fail(f"duplicate malicious-package record for {name}")
        if advisory in advisory_ids:
            fail(f"duplicate RustSec advisory record {advisory}")
        if not RUSTSEC_ADVISORY.fullmatch(advisory):
            fail(f"invalid RustSec advisory id {advisory!r}")
        parsed = urlparse(source)
        if parsed.scheme != "https" or parsed.netloc != "rustsec.org" or advisory not in parsed.path:
            fail(f"malicious-package source must be the matching rustsec.org advisory: {source!r}")
        denylist[name] = advisory
        advisory_ids.add(advisory)
    return denylist


def require_no_denied_packages(metadata: dict[str, Any], denylist: dict[str, str]) -> None:
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("cargo metadata packages field is missing or malformed")
    found: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            fail("cargo metadata contains a malformed package record")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            fail("cargo metadata package records require string name/version")
        advisory = denylist.get(name)
        if advisory is not None:
            found.append(f"{name} {version} ({advisory})")
    if found:
        fail("known-malicious package present in trusted workspace: " + ", ".join(sorted(found)))


def require_release_refresh_path(root: Path) -> None:
    workflow = (root / ".github/workflows/self-security.yml").read_text(encoding="utf-8")
    required = [
        "schedule:",
        "cron:",
        "scripts/validate_release_dependency_policy.py",
        "scripts/test_validate_release_dependency_policy.py",
        "cargo +1.98.0 audit --file Cargo.lock",
        "cargo +1.98.0 deny check advisories bans licenses sources",
    ]
    for token in required:
        if token not in workflow:
            fail(f"self-security workflow lost release-grade refresh/gate text {token!r}")

    forbidden = ["${{ inputs.", "working-directory:", "repository:"]
    for token in forbidden:
        if token in workflow:
            fail(f"self-security workflow contains target-redirection token {token!r}")


def validate(root: Path, metadata: dict[str, Any]) -> None:
    require_exact_toolchain(root)
    require_lockfile_shape(root)
    denylist = load_malicious_denylist(root)
    require_no_denied_packages(metadata, denylist)
    require_release_refresh_path(root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    try:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read cargo metadata: {error}")

    validate(root, metadata)
    print("release-dependency-policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

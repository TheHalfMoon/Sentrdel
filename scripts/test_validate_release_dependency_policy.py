#!/usr/bin/env python3
"""Unit tests for the T082 release dependency policy validator."""

from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("validate_release_dependency_policy.py")
SPEC = importlib.util.spec_from_file_location("validate_release_dependency_policy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ReleaseDependencyPolicyTests(unittest.TestCase):
    def test_known_malicious_package_fails_closed(self) -> None:
        metadata = {"packages": [{"name": "rands", "version": "1.0.0"}]}
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            POLICY.require_no_denied_packages(metadata, {"rands": "RUSTSEC-2025-0155"})

    def test_clean_metadata_passes_denylist(self) -> None:
        metadata = {"packages": [{"name": "serde", "version": "1.0.228"}]}
        POLICY.require_no_denied_packages(metadata, {"rands": "RUSTSEC-2025-0155"})

    def test_duplicate_denylist_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "docs/security"
            target.mkdir(parents=True)
            (target / "malicious-package-denylist.toml").write_text(
                """
[[package]]
name = "rands"
advisory = "RUSTSEC-2025-0155"
source = "https://rustsec.org/advisories/RUSTSEC-2025-0155.html"
reason = "malicious"
[[package]]
name = "rands"
advisory = "RUSTSEC-2026-0014"
source = "https://rustsec.org/advisories/RUSTSEC-2026-0014.html"
reason = "duplicate"
""".strip(),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                POLICY.load_malicious_denylist(root)

    def test_toolchain_and_lockfile_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rust-toolchain.toml").write_text(
                '[toolchain]\nchannel = "1.98.0"\nprofile = "minimal"\ncomponents = ["clippy", "rustfmt"]\n',
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            POLICY.require_exact_toolchain(root)
            POLICY.require_lockfile_shape(root)

    def test_refresh_path_must_not_redirect_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows"
            workflow.mkdir(parents=True)
            (workflow / "self-security.yml").write_text(
                """
on:
  schedule:
    - cron: '17 5 * * 1'
steps:
  - run: python3 scripts/validate_release_dependency_policy.py --metadata metadata.json
  - run: python3 scripts/test_validate_release_dependency_policy.py
  - run: cargo +1.98.0 audit --file Cargo.lock
  - run: cargo +1.98.0 deny check advisories bans licenses sources
""".strip(),
                encoding="utf-8",
            )
            POLICY.require_release_refresh_path(root)

            with (workflow / "self-security.yml").open("a", encoding="utf-8") as handle:
                handle.write("\nworking-directory: target-repo\n")
            with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                POLICY.require_release_refresh_path(root)


if __name__ == "__main__":
    unittest.main()

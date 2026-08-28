#!/usr/bin/env python3
"""Verify Sentrdel's live classic GitHub branch protection for main.

This script is intentionally fixed to TheHalfMoon/Sentrdel:main by default and
requires an administrator-capable token. It never treats CI success or a
checked-in desired policy as proof of live repository enforcement.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY = "TheHalfMoon/Sentrdel"
BRANCH = "main"
API_VERSION = "2022-11-28"
POLICY_PATH = Path(__file__).resolve().parents[1] / "docs/security/repository-governance-policy.json"


def fail(message: str) -> None:
    print(f"repository-governance: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def api_get(path: str, token: str) -> dict[str, Any] | list[Any]:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "sentrdel-t092-governance-verifier",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"GitHub API GET {path} returned HTTP {error.code}: {body[:500]}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        fail(f"GitHub API GET {path} failed: {error}")


def enabled(value: Any) -> bool:
    return isinstance(value, dict) and value.get("enabled") is True


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        fail("set GITHUB_TOKEN or GH_TOKEN to an administrator-capable token")

    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read desired policy {POLICY_PATH}: {error}")

    if policy.get("repository") != REPOSITORY or policy.get("branch") != BRANCH:
        fail("desired governance policy is not bound to the canonical repository/main branch")

    branch = api_get(f"/repos/{REPOSITORY}/branches/{BRANCH}", token)
    if not isinstance(branch, dict) or branch.get("protected") is not True:
        fail("live main branch is not reported as protected")

    protection = api_get(f"/repos/{REPOSITORY}/branches/{BRANCH}/protection", token)
    if not isinstance(protection, dict):
        fail("branch protection response is not an object")

    desired_checks = set(policy["required_status_checks"]["contexts"])
    status = protection.get("required_status_checks")
    if not isinstance(status, dict):
        fail("required status checks are not configured")

    live_checks = set(status.get("contexts") or [])
    for check in status.get("checks") or []:
        if isinstance(check, dict) and isinstance(check.get("context"), str):
            live_checks.add(check["context"])

    missing_checks = sorted(desired_checks - live_checks)
    if missing_checks:
        fail(f"required status checks are missing: {missing_checks}")
    if status.get("strict") is not True:
        fail("required status checks are not strict/up-to-date")

    if not enabled(protection.get("enforce_admins")):
        fail("administrator enforcement is not enabled")

    pull_requests = protection.get("required_pull_request_reviews")
    if not isinstance(pull_requests, dict):
        fail("pull requests are not required before merge")

    expected_approvals = policy["required_pull_request_reviews"]["required_approving_review_count"]
    if pull_requests.get("required_approving_review_count") != expected_approvals:
        fail(
            "required approving review count differs from policy: "
            f"expected {expected_approvals}, got {pull_requests.get('required_approving_review_count')}"
        )

    if not enabled(protection.get("required_conversation_resolution")):
        fail("required conversation resolution is not enabled")

    if enabled(protection.get("allow_force_pushes")):
        fail("force pushes are allowed")
    if enabled(protection.get("allow_deletions")):
        fail("branch deletion is allowed")

    if policy.get("required_linear_history") is False and enabled(protection.get("required_linear_history")):
        fail("live policy unexpectedly requires linear history; canonical merge-commit workflow would be blocked")

    rulesets = api_get(f"/repos/{REPOSITORY}/rulesets", token)
    active_rulesets = []
    if isinstance(rulesets, list):
        active_rulesets = [
            item
            for item in rulesets
            if isinstance(item, dict) and item.get("enforcement") == "active"
        ]

    head = branch.get("commit", {}).get("sha") if isinstance(branch.get("commit"), dict) else None
    print("repository-governance: PASS")
    print(f"repository={REPOSITORY}")
    print(f"branch={BRANCH}")
    print(f"head={head}")
    print(f"required_checks={','.join(sorted(desired_checks))}")
    print(f"active_repository_rulesets={len(active_rulesets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Apply Sentrdel's frozen T092 classic branch-protection policy.

The target is intentionally fixed to TheHalfMoon/Sentrdel:main. The script
requires an administrator-capable token and an explicit apply switch. It does
not accept an arbitrary repository/branch target.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY = "TheHalfMoon/Sentrdel"
BRANCH = "main"
API_VERSION = "2022-11-28"
ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs/security/repository-governance-policy.json"


def fail(message: str) -> None:
    print(f"repository-governance-apply: ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def api_put(path: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "sentrdel-t092-governance-applicator",
        },
        method="PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"GitHub API PUT {path} returned HTTP {error.code}: {body[:1000]}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        fail(f"GitHub API PUT {path} failed: {error}")

    if not isinstance(result, dict):
        fail("GitHub protection response was not an object")
    return result


def main() -> int:
    if os.environ.get("SENTRDEL_APPLY_REPOSITORY_GOVERNANCE") != "1":
        fail("set SENTRDEL_APPLY_REPOSITORY_GOVERNANCE=1 for this administrative mutation")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        fail("set GITHUB_TOKEN or GH_TOKEN to an administrator-capable token")

    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read desired policy {POLICY_PATH}: {error}")

    if policy.get("repository") != REPOSITORY or policy.get("branch") != BRANCH:
        fail("desired governance policy is not bound to the canonical repository/main branch")

    payload = {
        "required_status_checks": {
            "strict": bool(policy["required_status_checks"]["strict"]),
            "contexts": list(policy["required_status_checks"]["contexts"]),
        },
        "enforce_admins": bool(policy["enforce_admins"]),
        "required_pull_request_reviews": dict(policy["required_pull_request_reviews"]),
        "restrictions": policy["restrictions"],
        "required_conversation_resolution": bool(policy["required_conversation_resolution"]),
        "required_linear_history": bool(policy["required_linear_history"]),
        "allow_force_pushes": bool(policy["allow_force_pushes"]),
        "allow_deletions": bool(policy["allow_deletions"]),
        "allow_fork_syncing": bool(policy["allow_fork_syncing"]),
    }

    api_put(f"/repos/{REPOSITORY}/branches/{BRANCH}/protection", token, payload)
    print("repository-governance-apply: protection PUT accepted; verifying live state")

    env = os.environ.copy()
    verifier = ROOT / "scripts/verify_repository_governance.py"
    completed = subprocess.run(
        [sys.executable, str(verifier)],
        cwd=ROOT,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        fail("protection mutation returned but post-configuration verification failed")

    print("repository-governance-apply: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

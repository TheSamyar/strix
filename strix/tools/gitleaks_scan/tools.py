"""``gitleaks_scan`` — wrap the ``gitleaks`` binary to hunt leaked secrets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 180

HibpFetcher = Callable[[str], str]


def _shannon_entropy(value: str) -> float:
    """Shannon entropy in bits/char — higher means more random (key-like)."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def _hibp_fetcher(prefix: str) -> str:
    """Fetch the HIBP Pwned Passwords range for a SHA-1 prefix (k-anonymity)."""
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    with urlopen(Request(url, headers={"Add-Padding": "true"}), timeout=10) as resp:  # noqa: S310
        return str(resp.read().decode("utf-8", "replace"))


def hibp_pwned_count(secret: str, fetcher: HibpFetcher = _hibp_fetcher) -> int | None:
    """Return how many times ``secret`` appears in HIBP, or None on error.

    Uses k-anonymity: only the first 5 chars of the SHA-1 hash leave the
    host; the full secret is never sent.
    """
    if not secret:
        return None
    digest = hashlib.sha1(secret.encode("utf-8", "replace")).hexdigest().upper()  # noqa: S324
    prefix, suffix = digest[:5], digest[5:]
    try:
        body = fetcher(prefix)
    except (HTTPError, URLError, TimeoutError, OSError):
        return None
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def to_sarif(findings: list[dict[str, Any]], path: str) -> dict[str, Any]:
    """Convert findings to a minimal SARIF 2.1.0 document."""
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rule_id = str(f.get("rule") or "secret")
        rules.setdefault(rule_id, {"id": rule_id})
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"Leaked secret ({rule_id})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("file") or ""},
                            "region": {"startLine": f.get("line") or 1},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "informationUri": "https://github.com/gitleaks/gitleaks",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {"SRCROOT": {"uri": path}},
                "results": results,
            }
        ],
    }


def _scan_impl(path: str, no_git: bool, check_hibp: bool = False) -> dict[str, Any]:
    if shutil.which("gitleaks") is None:
        return {"error": "gitleaks binary not found on PATH", "hint": "install gitleaks"}

    report_path = Path(tempfile.mkstemp(prefix="gitleaks-", suffix=".json")[1])
    try:
        argv = [
            "gitleaks",
            "detect",
            "--source",
            path,
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--exit-code",
            "0",
        ]
        if no_git:
            argv.append("--no-git")
        try:
            subprocess.run(argv, capture_output=True, timeout=_TIMEOUT_SECONDS, check=False)  # noqa: S603
        except subprocess.TimeoutExpired:
            return {"error": f"gitleaks timed out after {_TIMEOUT_SECONDS}s", "path": path}

        try:
            raw = report_path.read_text(encoding="utf-8")
        except OSError as e:
            return {"error": f"could not read gitleaks report: {e}", "path": path}
        report = json.loads(raw) if raw.strip() else []
    except json.JSONDecodeError as e:
        return {"error": f"invalid gitleaks report: {e}", "path": path}
    finally:
        report_path.unlink(missing_ok=True)

    findings = [
        {
            "rule": f.get("RuleID"),
            "file": f.get("File"),
            "line": f.get("StartLine"),
            "commit": f.get("Commit"),
            "author": f.get("Author"),
            "date": f.get("Date"),
            "secret": f.get("Secret") or "",
            "entropy": _shannon_entropy(f.get("Secret") or ""),
        }
        for f in report
    ]
    if check_hibp:
        for finding in findings:
            finding["hibp_pwned_count"] = hibp_pwned_count(str(finding["secret"]))
    # Highest-entropy first — most key-like secrets surface at the top.
    findings.sort(key=lambda f: f["entropy"], reverse=True)
    return {"path": path, "count": len(findings), "findings": findings}


@function_tool(timeout=_TIMEOUT_SECONDS + 20)
async def gitleaks_scan(
    ctx: RunContextWrapper,
    path: str,
    no_git: bool = False,
    check_hibp: bool = False,
    sarif: bool = False,
) -> str:
    """Scan a repository for leaked secrets with the ``gitleaks`` binary.

    Runs ``gitleaks detect`` over the given repo, walking its git history
    by default. Matched secret values are returned in full — local runs
    keep the raw value so evidence can be filed without redaction. Each
    finding is scored with Shannon ``entropy`` (bits/char) and findings are
    ordered highest-entropy first to surface the most key-like secrets.

    Requires the ``gitleaks`` binary on PATH; if it is missing the tool
    returns ``{error, hint}`` rather than raising.

    Args:
        path: Path to the repository directory to scan.
        no_git: When True, scan the filesystem only (``--no-git``) and
            skip git history.
        check_hibp: When True, check each secret against Have I Been Pwned
            Pwned Passwords via k-anonymity (only a SHA-1 prefix leaves the
            host) and add ``hibp_pwned_count`` per finding.
        sarif: When True, include a SARIF 2.1.0 document under ``sarif`` for
            CI ingestion.
    """
    del ctx
    result = await asyncio.to_thread(_scan_impl, path, no_git, check_hibp)
    if sarif and "findings" in result:
        result["sarif"] = to_sarif(result["findings"], path)
    return json.dumps(result, ensure_ascii=False, default=str)

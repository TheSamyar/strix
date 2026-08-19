"""Dependency-confusion / typosquat detection.

Known-CVE scanners (osv/npm audit) find *vulnerable published* packages.
This finds the other class: names an attacker can register on a public
registry to hijack a build (dependency confusion) and near-miss squats of
popular packages. Pairs with the ``supply_chain_dependency_confusion`` skill.

Pure helpers are module-level so tests can call them with a fake fetcher;
the ``@function_tool`` wrapper is the agent-facing surface.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agents import RunContextWrapper, function_tool


# Small curated set of frequently-squatted packages. Not exhaustive — a
# ponytail: static list, extend when a squat class is missed rather than
# pulling a full registry dump.
_POPULAR = {
    "npm": {
        "react", "lodash", "axios", "express", "chalk", "commander", "moment",
        "request", "debug", "async", "webpack", "babel", "jest", "eslint",
        "typescript", "next", "vue", "dotenv", "uuid", "cross-env", "colors",
    },
    "pypi": {
        "requests", "numpy", "pandas", "flask", "django", "urllib3", "boto3",
        "setuptools", "pytest", "pyyaml", "click", "jinja2", "pillow", "scipy",
        "cryptography", "sqlalchemy", "fastapi", "python-dateutil", "certifi",
    },
}

_REGISTRY_URL = {
    "npm": "https://registry.npmjs.org/{name}",
    "pypi": "https://pypi.org/pypi/{name}/json",
}

Fetcher = Callable[[str], int]


def _default_fetcher(url: str) -> int:
    """Return the HTTP status for a HEAD-ish GET; 404 => name unclaimed."""
    try:
        with urlopen(Request(url, method="GET"), timeout=10) as resp:  # noqa: S310
            return int(resp.status)
    except HTTPError as exc:
        return int(exc.code)
    except (URLError, TimeoutError, OSError):
        return 0  # network error — unknown, not "unclaimed"


def parse_manifest(content: str, ecosystem: str) -> list[str]:
    """Extract dependency names from a manifest. ``ecosystem`` in {npm, pypi, go}."""
    names: list[str] = []
    if ecosystem == "npm":
        data = json.loads(content or "{}")
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            names.extend((data.get(key) or {}).keys())
    elif ecosystem == "pypi":
        # requirements.txt lines OR pyproject.toml [project]/poetry tables.
        stripped = content.lstrip()
        if stripped.startswith("[") or "[project]" in content or "[tool.poetry" in content:
            data = tomllib.loads(content)
            project = data.get("project", {})
            names.extend(_pep508_name(d) for d in project.get("dependencies", []) or [])
            for group in (project.get("optional-dependencies", {}) or {}).values():
                names.extend(_pep508_name(d) for d in group)
            poetry = data.get("tool", {}).get("poetry", {})
            names.extend(k for k in (poetry.get("dependencies") or {}) if k.lower() != "python")
        else:
            for raw_line in content.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                names.append(_pep508_name(line))
    elif ecosystem == "go":
        names.extend(
            m.group(1)
            for m in re.finditer(r"^\s*([\w./-]+)\s+v\d[\w.\-+]*", content, re.MULTILINE)
        )
    return [n for n in (n.strip() for n in names) if n]


def _pep508_name(spec: str) -> str:
    return re.split(r"[<>=!~;\[\s]", spec.strip(), maxsplit=1)[0]


def _edit_distance_le1(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` differ by one edit or one adjacent transposition.

    Damerau-style: catches substitution, insertion, deletion, and swapped
    adjacent characters (``reqeusts``/``loadsh``) — all common squat shapes.
    """
    if a == b:
        return False  # identical is the canonical package, not a squat
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:  # single substitution
            return True
        # single adjacent transposition
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        )
    # insertion/deletion: walk the shorter against the longer
    short, lng = (a, b) if la < lb else (b, a)
    i = j = 0
    diff = 0
    while i < len(short) and j < len(lng):
        if short[i] == lng[j]:
            i += 1
            j += 1
        else:
            diff += 1
            j += 1
            if diff > 1:
                return False
    return True


def typosquat_of(name: str, ecosystem: str) -> str | None:
    """Return the popular package this name mimics (≤1 edit or separator swap)."""
    canon = name.lower()
    normalized = re.sub(r"[-_.]", "-", canon)
    for pop in _POPULAR.get(ecosystem, set()):
        if pop == canon:
            return None  # it *is* the popular package
        if re.sub(r"[-_.]", "-", pop) == normalized and pop != canon:
            return pop  # differs only by separator/case
        if _edit_distance_le1(canon, pop):
            return pop
    return None


def check_names(
    names: list[str],
    ecosystem: str,
    fetcher: Fetcher = _default_fetcher,
    internal_prefixes: tuple[str, ...] = (),
) -> list[dict[str, object]]:
    """Classify each name for confusion / typosquat risk.

    ``internal_prefixes`` marks names that *should* resolve from a private
    registry; if such a name is unclaimed publicly it's a confusion risk.
    """
    tmpl = _REGISTRY_URL.get(ecosystem)
    findings: list[dict[str, object]] = []
    for name in dict.fromkeys(names):  # dedupe, keep order
        status = fetcher(tmpl.format(name=name)) if tmpl else 0
        claimed = status == 200
        squat = typosquat_of(name, ecosystem)
        is_internal = any(
            name.lower().startswith(p.lower()) or name.startswith(f"@{p}")
            for p in internal_prefixes
        )
        risk = None
        if status == 404 and (is_internal or not squat):
            risk = "dependency_confusion"  # unclaimed on public registry
        elif squat:
            risk = "typosquat"
        if risk:
            findings.append(
                {
                    "name": name,
                    "ecosystem": ecosystem,
                    "public_status": status,
                    "claimed": claimed,
                    "typosquat_of": squat,
                    "internal": is_internal,
                    "risk": risk,
                }
            )
    return findings


@function_tool(timeout=120)
async def check_dependency_confusion(
    ctx: RunContextWrapper,
    manifest_content: str,
    ecosystem: str,
    internal_prefixes: list[str] | None = None,
) -> str:
    """Flag dependency-confusion and typosquat risks in a manifest.

    Complements CVE-based SCA: it queries the public registry to find (a)
    internal-looking packages *unclaimed* publicly (an attacker could
    register them and hijack the build) and (b) near-miss squats of popular
    packages. Load the ``supply_chain_dependency_confusion`` skill for the
    methodology and how to validate/report.

    Args:
        manifest_content: Raw text of the manifest (package.json,
            requirements.txt, pyproject.toml, or go.mod).
        ecosystem: One of ``npm``, ``pypi``, ``go``.
        internal_prefixes: Optional company/scope prefixes (e.g. ``["@acme",
            "acme-"]``) that should resolve from a private registry — an
            unclaimed public name with such a prefix is a confusion risk.
    """
    del ctx
    ecosystem = (ecosystem or "").lower().strip()
    if ecosystem not in ("npm", "pypi", "go"):
        return json.dumps({"error": f"unsupported ecosystem '{ecosystem}' (use npm|pypi|go)"})
    try:
        names = parse_manifest(manifest_content, ecosystem)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        return json.dumps({"error": f"failed to parse manifest: {exc}"})
    findings = check_names(names, ecosystem, internal_prefixes=tuple(internal_prefixes or ()))
    return json.dumps(
        {
            "success": True,
            "ecosystem": ecosystem,
            "dependencies_checked": len(set(names)),
            "findings": findings,
        },
        ensure_ascii=False,
    )

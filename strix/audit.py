"""Playbook + vendor adapters for `strix audit`."""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from strix.interface.scan_setup import _resolve_api_spec
from strix.interface.utils import (
    assign_workspace_subdirs,
    dedupe_local_targets,
    infer_target_type,
    read_target_list_file,
)
from strix.report.sarif import write_sarif
from strix.report.writer import write_executive_report, write_vulnerabilities


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)


SCAN_MODES = ("quick", "standard", "deep")
SITE_PROFILES = ("auto", "generic", "nextjs", "wordpress", "fastapi")
CONCRETE_SITE_PROFILES = ("generic", "nextjs", "wordpress", "fastapi")


@dataclass(frozen=True)
class AuditJob:
    id: str
    title: str
    skills: tuple[str, ...]
    task: str


@dataclass(frozen=True)
class AuditAuth:
    cookie: str | None = None
    headers: tuple[str, ...] = ()
    login_url: str | None = None
    login_username: str | None = None
    login_password: str | None = None

    def has_auth(self) -> bool:
        return any(
            (
                self.cookie,
                self.headers,
                self.login_url,
                self.login_username,
                self.login_password,
            )
        )

    def to_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.cookie:
            env["STRIX_AUTH_COOKIE"] = self.cookie
        for index, header in enumerate(self.headers, start=1):
            env[f"STRIX_AUTH_HEADER_{index}"] = header
        if self.login_url:
            env["STRIX_LOGIN_URL"] = self.login_url
        if self.login_username:
            env["STRIX_LOGIN_USERNAME"] = self.login_username
        if self.login_password:
            env["STRIX_LOGIN_PASSWORD"] = self.login_password
        return env

    def to_redacted_dict(self) -> dict[str, bool | int]:
        return {
            "auth_cookie": bool(self.cookie),
            "auth_headers": len(self.headers),
            "login_url": bool(self.login_url),
            "login_username": bool(self.login_username),
            "login_password": bool(self.login_password),
        }


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    body: str


@dataclass(frozen=True)
class SiteProfileDetection:
    requested: str
    resolved: str
    target_urls: tuple[str, ...]
    evidence: tuple[str, ...]
    scores: dict[str, int]
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "resolved": self.resolved,
            "target_urls": list(self.target_urls),
            "evidence": list(self.evidence),
            "scores": self.scores,
            "errors": list(self.errors),
        }


_HARVEST = AuditJob(
    "harvest",
    "Domain harvest",
    (),
    "Deterministic host expand, OpenAPI/catalog ingest, and unauth walk.",
)
_FASTAPI_AUTH = AuditJob(
    "fastapi_auth",
    "FastAPI auth specialist",
    ("fastapi", "oauth", "authentication_jwt"),
    "Test OAuth/DCR/CORS, X-Admin-Impersonate-*, and FastAPI auth dependencies.",
)

_GENERIC_TASK_PREFIX = (
    "Read attack-surface / walk artifacts already on disk for this run; do not re-harvest. "
    "Prove with validate_finding before create_vulnerability_report. "
    "Stay inside this specialist class; do not spawn sub-agents. "
)

_QUICK: tuple[AuditJob, ...] = (
    AuditJob(
        "recon",
        "Recon specialist",
        ("asset_discovery",),
        _GENERIC_TASK_PREFIX
        + "Run profile_target, discover_assets, and walk_unauth; persist surfaces with "
        "record_endpoint; file gaps via coverage_report. Do not deep-exploit.",
    ),
    AuditJob(
        "auth",
        "Auth specialist",
        ("authentication_jwt", "csrf"),
        _GENERIC_TASK_PREFIX
        + "Run jwt_audit, session_invalidation_probe, csrf_probe, and oauth_probe; persist "
        "usable creds with store_credential.",
    ),
    AuditJob(
        "injection",
        "Injection specialist",
        ("sql_injection", "xss", "rce"),
        _GENERIC_TASK_PREFIX
        + "Run param_discover, then injection_fuzz, stored_probe, and deep_fuzz on SQLi, XSS, "
        "and RCE surfaces.",
    ),
    AuditJob(
        "access",
        "Access-control specialist",
        ("idor", "broken_function_level_authorization"),
        _GENERIC_TASK_PREFIX
        + "Run authz_probe and authz_matrix; re-check unauth reachability with walk_unauth for "
        "IDOR and function-level authorization.",
    ),
)
_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "ssrf_files",
        "SSRF and files specialist",
        ("ssrf", "path_traversal_lfi_rfi", "insecure_file_uploads"),
        _GENERIC_TASK_PREFIX + "Run ssrf_probe, lfi_probe, upload_probe, and xxe_probe.",
    ),
    AuditJob(
        "secrets_deps",
        "Secrets and deps specialist",
        ("information_disclosure", "dependency_cve_scanning"),
        _GENERIC_TASK_PREFIX
        + "Run frontend_secret_scan, gitleaks_scan, osv_scan, and storage_probe.",
    ),
)
_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "logic",
        "Logic specialist",
        ("business_logic", "race_conditions"),
        _GENERIC_TASK_PREFIX
        + "This is the business-logic pass: run race_probe and authz_probe on checkout, "
        "password-reset, invite, and admin workflows.",
    ),
    AuditJob(
        "deser_ssti",
        "Deser/SSTI specialist",
        ("insecure_deserialization", "ssti"),
        _GENERIC_TASK_PREFIX
        + "Test insecure deserialization and SSTI; run stored_probe and injection_fuzz on "
        "template parameters.",
    ),
)


_NEXTJS_QUICK: tuple[AuditJob, ...] = (
    AuditJob(
        "nextjs_recon",
        "Next.js recon specialist",
        ("asset_discovery", "frameworks/nextjs"),
        "Fingerprint the deployed Next.js app, crawl public routes, mine build artifacts, "
        "source maps, manifests, sitemap/robots, and client bundles. Record deployed routes "
        "and parameters before deeper testing.",
    ),
    AuditJob(
        "nextjs_routes",
        "Next.js routes and data specialist",
        ("frameworks/nextjs", "information_disclosure", "xss"),
        "Test App Router, Pages Router, API routes, Route Handlers, Server Actions, RSC/Flight "
        "payloads, SSR/SSG/ISR data exposure, __NEXT_DATA__ over-fetching, and hydration/client "
        "bundle leaks.",
    ),
    AuditJob(
        "nextjs_auth_cache",
        "Next.js auth and cache specialist",
        ("frameworks/nextjs", "authentication_jwt", "csrf", "idor"),
        "Test middleware bypass, NextAuth callbackUrl/provider flows, auth enforcement drift, "
        "IDOR, cache key confusion, Vary/ETag mistakes, preview/draft mode, and personalized "
        "data served from shared caches.",
    ),
    AuditJob(
        "nextjs_injection_ssrf",
        "Next.js injection and SSRF specialist",
        ("frameworks/nextjs", "sql_injection", "xss", "ssrf", "rce"),
        "Test query/body parameters, image optimizer SSRF, custom loaders, server action inputs, "
        "method/content-type switching, open redirects, SSRF, XSS, SQLi, and RCE candidates.",
    ),
)
_NEXTJS_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "nextjs_files_uploads",
        "Next.js file and upload specialist",
        ("frameworks/nextjs", "path_traversal_lfi_rfi", "insecure_file_uploads"),
        "Test file-serving routes, download/export endpoints, upload handlers, path normalization, "
        "and traversal or content-type bypasses.",
    ),
    AuditJob(
        "nextjs_deps_exposure",
        "Next.js dependency and exposure specialist",
        ("frameworks/nextjs", "dependency_cve_scanning", "information_disclosure"),
        "Identify exposed versions, vulnerable deployed packages, public sourcemaps, debug "
        "endpoints, and leaked NEXT_PUBLIC or accidental secret material.",
    ),
)
_NEXTJS_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "nextjs_logic_races",
        "Next.js logic and race specialist",
        ("frameworks/nextjs", "business_logic", "race_conditions"),
        "Test high-value workflows for authorization drift, race conditions, replay, and business "
        "logic flaws in route handlers and server actions.",
    ),
    AuditJob(
        "nextjs_deser_ssti",
        "Next.js deserialization and template specialist",
        ("frameworks/nextjs", "insecure_deserialization", "ssti"),
        "Test serialization boundaries, signed payload handling, template/markdown rendering, and "
        "dangerous server-side data parsing paths.",
    ),
)

_WORDPRESS_QUICK: tuple[AuditJob, ...] = (
    AuditJob(
        "wordpress_recon",
        "WordPress recon specialist",
        ("tooling/wpscan", "information_disclosure"),
        "Use WPScan safe enumeration only: version, plugins, themes, and users where useful. "
        "Also check /wp-json/, /wp-login.php, /xmlrpc.php, /wp-admin/admin-ajax.php, robots, "
        "sitemaps, exposed backups, and public upload paths. Do not brute force credentials.",
    ),
    AuditJob(
        "wordpress_components",
        "WordPress component CVE specialist",
        ("tooling/wpscan", "dependency_cve_scanning", "information_disclosure"),
        "Correlate WordPress core, plugin, and theme versions with known CVEs using WPScan, "
        "nuclei, and public evidence. Validate exploitability before filing; scanner labels alone "
        "are not sufficient.",
    ),
    AuditJob(
        "wordpress_auth_access",
        "WordPress auth and access specialist",
        ("csrf", "idor", "broken_function_level_authorization"),
        "Test REST API permissions, admin-ajax actions, nonce/CSRF weaknesses, user enumeration, "
        "role/capability bypasses, unauthenticated privileged actions, and authenticated coverage "
        "when auth env vars are present. Do not brute force credentials.",
    ),
    AuditJob(
        "wordpress_injection_uploads",
        "WordPress injection and upload specialist",
        ("sql_injection", "xss", "rce", "insecure_file_uploads", "path_traversal_lfi_rfi"),
        "Test plugin/theme endpoints, search/forms, REST parameters, AJAX actions, media/upload "
        "surfaces, file reads, XSS, SQLi, RCE, and traversal candidates.",
    ),
)
_WORDPRESS_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "wordpress_ssrf_xmlrpc",
        "WordPress SSRF and XML-RPC specialist",
        ("ssrf", "xxe", "tooling/wpscan"),
        "Test XML-RPC exposure, pingback behavior, oEmbed/fetching features, webhooks, imports, "
        "and SSRF-like URL fetch surfaces without destructive amplification.",
    ),
    AuditJob(
        "wordpress_secrets_files",
        "WordPress secrets and files specialist",
        ("information_disclosure", "path_traversal_lfi_rfi"),
        "Look for exposed wp-config backups, debug logs, database dumps, install/upgrade "
        "leftovers, directory indexing, readable uploads, and sensitive files.",
    ),
)
_WORDPRESS_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob(
        "wordpress_logic_races",
        "WordPress logic and race specialist",
        ("business_logic", "race_conditions"),
        "Test commerce, membership, forms, booking, and account workflows for authorization, "
        "replay, race, and state-machine flaws.",
    ),
    AuditJob(
        "wordpress_deser_ssti",
        "WordPress deserialization and template specialist",
        ("insecure_deserialization", "ssti", "rce"),
        "Test plugin/theme serialization, import/export, template rendering, shortcode processing, "
        "and dangerous PHP object or template injection paths.",
    ),
)


def _jobs_for_mode(
    mode: str,
    quick: tuple[AuditJob, ...],
    standard: tuple[AuditJob, ...],
    deep: tuple[AuditJob, ...],
) -> tuple[AuditJob, ...]:
    if mode == "quick":
        return quick
    if mode == "standard":
        return quick + standard
    if mode == "deep":
        return quick + standard + deep
    raise ValueError(f"unknown scan-mode {mode!r}; expected one of {SCAN_MODES}")


def jobs_for_mode(mode: str, *, site_profile: str = "generic") -> tuple[AuditJob, ...]:
    if site_profile not in CONCRETE_SITE_PROFILES:
        raise ValueError(
            f"unknown site-profile {site_profile!r}; expected one of {CONCRETE_SITE_PROFILES}"
        )
    if site_profile == "nextjs":
        return _jobs_for_mode(mode, _NEXTJS_QUICK, _NEXTJS_STANDARD_EXTRA, _NEXTJS_DEEP_EXTRA)
    if site_profile == "wordpress":
        return _jobs_for_mode(
            mode,
            _WORDPRESS_QUICK,
            _WORDPRESS_STANDARD_EXTRA,
            _WORDPRESS_DEEP_EXTRA,
        )
    if site_profile == "fastapi":
        return (
            _HARVEST,
            _FASTAPI_AUTH,
            *_jobs_for_mode(mode, _QUICK, _STANDARD_EXTRA, _DEEP_EXTRA),
        )
    return _jobs_for_mode(mode, _QUICK, _STANDARD_EXTRA, _DEEP_EXTRA)


def jobs_for_profiles(mode: str, profiles: Sequence[str]) -> tuple[AuditJob, ...]:
    wanted = tuple(profile for profile in profiles if profile in CONCRETE_SITE_PROFILES)
    if not wanted:
        wanted = ("generic",)
    seen: set[str] = set()
    out: list[AuditJob] = []

    def add(jobs: Sequence[AuditJob]) -> None:
        for job in jobs:
            if job.id not in seen:
                seen.add(job.id)
                out.append(job)

    if "fastapi" in wanted:
        add((_HARVEST, _FASTAPI_AUTH))
        add(_jobs_for_mode(mode, _QUICK, _STANDARD_EXTRA, _DEEP_EXTRA))
    if "nextjs" in wanted:
        add(_jobs_for_mode(mode, _NEXTJS_QUICK, _NEXTJS_STANDARD_EXTRA, _NEXTJS_DEEP_EXTRA))
    if "wordpress" in wanted:
        add(
            _jobs_for_mode(
                mode,
                _WORDPRESS_QUICK,
                _WORDPRESS_STANDARD_EXTRA,
                _WORDPRESS_DEEP_EXTRA,
            )
        )
    if "generic" in wanted and "fastapi" not in wanted:
        add(_jobs_for_mode(mode, _QUICK, _STANDARD_EXTRA, _DEEP_EXTRA))
    return tuple(out)


def auth_from_args(args: Any) -> AuditAuth:
    headers = tuple(str(header).strip() for header in (getattr(args, "auth_header", None) or []))
    invalid = [header for header in headers if ":" not in header or header.startswith(":")]
    if invalid:
        raise ValueError('--auth-header must use "Name: value" format')
    return AuditAuth(
        cookie=getattr(args, "auth_cookie", None),
        headers=headers,
        login_url=getattr(args, "login_url", None),
        login_username=getattr(args, "login_username", None),
        login_password=getattr(args, "login_password", None),
    )


def web_target_urls(targets_info: list[dict[str, Any]]) -> list[str]:
    return [
        str(item.get("details", {}).get("target_url"))
        for item in targets_info
        if item.get("type") == "web_application" and item.get("details", {}).get("target_url")
    ]


def _default_fetcher(url: str, headers: dict[str, str]) -> FetchResult:
    if urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("only http and https URLs can be profiled")
    request = Request(url, headers=headers, method="GET")  # noqa: S310
    try:
        with urlopen(request, timeout=5) as response:  # noqa: S310
            raw = response.read(512_000)
            body = raw.decode("utf-8", errors="replace")
            return FetchResult(
                url=url,
                status=int(getattr(response, "status", 0) or 0),
                headers={str(k).lower(): str(v) for k, v in response.headers.items()},
                body=body,
            )
    except HTTPError as exc:
        raw = exc.read(64_000)
        return FetchResult(
            url=url,
            status=exc.code,
            headers={str(k).lower(): str(v) for k, v in exc.headers.items()},
            body=raw.decode("utf-8", errors="replace"),
        )


def _auth_headers(auth: AuditAuth | None) -> dict[str, str]:
    headers = {"User-Agent": "strix-audit/1.0"}
    if auth is None:
        return headers
    if auth.cookie:
        headers["Cookie"] = auth.cookie
    for raw in auth.headers:
        name, value = raw.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def _append_signal(evidence: list[str], label: str) -> None:
    if label not in evidence:
        evidence.append(label)


def _score_response(label: str, result: FetchResult, evidence: list[str]) -> dict[str, int]:
    body = result.body.lower()
    headers = {key.lower(): value.lower() for key, value in result.headers.items()}
    scores = {"nextjs": 0, "wordpress": 0, "fastapi": 0}

    if "__next_data__" in body:
        scores["nextjs"] += 3
        _append_signal(evidence, f"{label}: __NEXT_DATA__")
    if "/_next/" in body or "_next/static" in body:
        scores["nextjs"] += 2
        _append_signal(evidence, f"{label}: _next static assets")
    if "next-action" in body or "rsc" in headers.get("content-type", ""):
        scores["nextjs"] += 1
        _append_signal(evidence, f"{label}: RSC/Server Action hints")
    if "next.js" in headers.get("x-powered-by", ""):
        scores["nextjs"] += 2
        _append_signal(evidence, f"{label}: x-powered-by Next.js")

    if "wp-content" in body:
        scores["wordpress"] += 2
        _append_signal(evidence, f"{label}: wp-content")
    if "wp-includes" in body:
        scores["wordpress"] += 1
        _append_signal(evidence, f"{label}: wp-includes")
    if "wp-json" in body or '"wp/v2"' in body or ('"namespaces"' in body and "wp/" in body):
        scores["wordpress"] += 2
        _append_signal(evidence, f"{label}: wp-json")
    if "wordpress" in body or "wordpress" in headers.get("x-pingback", ""):
        scores["wordpress"] += 2
        _append_signal(evidence, f"{label}: WordPress marker")
    _score_fastapi(label, result, body, headers, evidence, scores)
    return scores


def _score_fastapi(
    label: str,
    result: FetchResult,
    body: str,
    headers: dict[str, str],
    evidence: list[str],
    scores: dict[str, int],
) -> None:
    if "uvicorn" in headers.get("server", ""):
        scores["fastapi"] += 3
        _append_signal(evidence, f"{label}: server uvicorn")
    if label == "openapi" and result.status == 200 and "openapi" in body:
        scores["fastapi"] += 3
        _append_signal(evidence, f"{label}: openapi.json")
    if label == "mcp" and result.status in {401, 403, 406}:
        scores["fastapi"] += 2
        _append_signal(evidence, f"{label}: /mcp auth")
    mcp_body = label == "mcp" and result.status == 200
    if mcp_body and any(marker in body for marker in ("jsonrpc", "openapi", '"mcp"', "mcp_url")):
        scores["fastapi"] += 2
        _append_signal(evidence, f"{label}: /mcp")
    if "/mcp" in body or "fastapi" in body:
        scores["fastapi"] += 1
        _append_signal(evidence, f"{label}: FastAPI/MCP hint")


def detect_site_profile(
    urls: list[str],
    requested: str,
    *,
    auth: AuditAuth | None = None,
    fetcher: Callable[[str, dict[str, str]], FetchResult] | None = None,
) -> SiteProfileDetection:
    if requested not in SITE_PROFILES:
        raise ValueError(f"unknown site-profile {requested!r}; expected one of {SITE_PROFILES}")
    empty_scores = {"nextjs": 0, "wordpress": 0, "fastapi": 0}
    if requested != "auto":
        return SiteProfileDetection(
            requested=requested,
            resolved=requested,
            target_urls=tuple(urls),
            evidence=(f"site profile forced to {requested}",),
            scores=empty_scores,
        )
    if not urls:
        return SiteProfileDetection(
            requested=requested,
            resolved="generic",
            target_urls=(),
            evidence=("no live URL targets to profile",),
            scores=empty_scores,
        )

    resolved_fetcher = fetcher or _default_fetcher
    headers = _auth_headers(auth)
    evidence: list[str] = []
    errors: list[str] = []
    totals = {"nextjs": 0, "wordpress": 0, "fastapi": 0}

    for target_url in urls:
        for label, url in (
            ("root", target_url),
            ("wp-json", urljoin(target_url.rstrip("/") + "/", "wp-json/")),
            ("wp-login", urljoin(target_url.rstrip("/") + "/", "wp-login.php")),
            ("openapi", urljoin(target_url.rstrip("/") + "/", "openapi.json")),
            ("mcp", urljoin(target_url.rstrip("/") + "/", "mcp")),
        ):
            try:
                result = resolved_fetcher(url, headers)
            except (OSError, URLError, TimeoutError, ValueError) as exc:
                errors.append(f"{url}: {exc}")
                continue
            scores = _score_response(label, result, evidence)
            totals["nextjs"] += scores["nextjs"]
            totals["wordpress"] += scores["wordpress"]
            totals["fastapi"] += scores["fastapi"]

    if totals["nextjs"] >= 2 and totals["wordpress"] >= 2:
        resolved = "generic"
    elif (
        totals["fastapi"] >= 2
        and totals["fastapi"] > totals["nextjs"]
        and totals["fastapi"] > totals["wordpress"]
    ):
        resolved = "fastapi"
    elif totals["nextjs"] > totals["wordpress"] and totals["nextjs"] >= 2:
        resolved = "nextjs"
    elif totals["wordpress"] > totals["nextjs"] and totals["wordpress"] >= 2:
        resolved = "wordpress"
    else:
        resolved = "generic"

    return SiteProfileDetection(
        requested=requested,
        resolved=resolved,
        target_urls=tuple(urls),
        evidence=tuple(evidence) or ("no framework-specific signals found",),
        scores=totals,
        errors=tuple(errors),
    )


def recommended_tools_for_profile(site_profile: str) -> tuple[str, ...]:
    base = ("httpx", "whatweb", "nuclei", "nikto")
    if site_profile == "wordpress":
        return (*base, "wpscan")
    return base


def missing_recommended_tools(
    site_profile: str,
    *,
    path_lookup: Callable[[str], str | None],
) -> tuple[str, ...]:
    return tuple(
        tool for tool in recommended_tools_for_profile(site_profile) if not path_lookup(tool)
    )


MCP_CHDIR_SNIPPET = (
    "import os,sys; os.chdir(sys.argv[1]); "
    "from strix.interface.mcp_server import run_mcp; "
    "raise SystemExit(run_mcp(sys.argv[2:]))"
)

VENDOR_BINARIES: dict[str, tuple[str, ...]] = {
    "claude": ("claude",),
    "cursor": ("cursor-agent", "agent"),
    "codex": ("codex",),
}
PATH_DEFAULT_ORDER = ("claude", "cursor", "codex")
AGENT_HINTS = {
    "claude": "Install Claude Code and ensure `claude` is on PATH.",
    "cursor": (
        "Install Cursor Agent (`cursor-agent` or `agent`). The `cursor` IDE binary is not an agent."
    ),
    "codex": "Install Codex and ensure `codex` is on PATH.",
}


def mcp_argv(original_cwd: str, run_name: str) -> list[str]:
    return [
        sys.executable,
        "-c",
        MCP_CHDIR_SNIPPET,
        original_cwd,
        "--run-name",
        run_name,
        "--no-seed",
    ]


def write_mcp_config_json(command: str, args: list[str]) -> dict[str, Any]:
    return {
        "mcpServers": {
            "strix": {"type": "stdio", "command": command, "args": args},
        }
    }


def resolve_agent(
    explicit: str | None,
    *,
    path_lookup: Callable[[str], str | None],
) -> tuple[str, str]:
    if explicit is not None:
        if explicit not in VENDOR_BINARIES:
            raise ValueError(f"unknown agent {explicit!r}")
        for name in VENDOR_BINARIES[explicit]:
            found = path_lookup(name)
            if found:
                return explicit, found
        raise FileNotFoundError(AGENT_HINTS[explicit])
    for agent in PATH_DEFAULT_ORDER:
        for name in VENDOR_BINARIES[agent]:
            found = path_lookup(name)
            if found:
                return agent, found
    raise FileNotFoundError(" ".join(AGENT_HINTS.values()))


def claude_argv(
    binary: str,
    prompt: str,
    mcp_config: Path,
    worktree_name: str | None = None,
) -> list[str]:
    argv = [
        binary,
        "-p",
        "--dangerously-skip-permissions",
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--output-format",
        "json",
    ]
    if worktree_name:
        argv.extend(["-w", worktree_name])
    return [*argv, prompt]


def cursor_argv(binary: str, prompt: str, workspace: Path) -> list[str]:
    return [
        binary,
        "-p",
        "--force",
        "--sandbox",
        "disabled",
        "--approve-mcps",
        "--trust",
        "--workspace",
        str(workspace),
        prompt,
    ]


def codex_argv(
    binary: str,
    prompt: str,
    worker_cwd: Path,
    original_cwd: str,
    run_name: str,
) -> list[str]:
    mcp = mcp_argv(original_cwd, run_name)
    args_json = json.dumps(mcp[1:])
    return [
        binary,
        "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "-C",
        str(worker_cwd),
        "-c",
        f"mcp_servers.strix_audit.command={json.dumps(mcp[0])}",
        "-c",
        f"mcp_servers.strix_audit.args={args_json}",
        "-c",
        f"mcp_servers.strix_audit.cwd={json.dumps(original_cwd)}",
        prompt,
    ]


def load_worker_reports(parent: Path, job_ids: Sequence[str]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for job_id in job_ids:
        path = parent / "workers" / job_id / "vulnerabilities.json"
        if not path.is_file():
            logger.warning("audit merge: missing %s", path)
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("audit merge: corrupt %s", path)
            continue
        if not isinstance(payload, list):
            logger.warning("audit merge: not a list %s", path)
            continue
        reports.extend(item for item in payload if isinstance(item, dict))
    return reports


def remint_ids(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    minted: list[dict[str, Any]] = []
    for index, report in enumerate(reports, start=1):
        updated = dict(report)
        updated["id"] = f"vuln-{index:04d}"
        minted.append(updated)
    return minted


def write_parent_reports(
    parent: Path,
    reports: list[dict[str, Any]],
    *,
    jobs_summary: str,
) -> None:
    parent.mkdir(parents=True, exist_ok=True)
    write_vulnerabilities(parent, reports, saved_vuln_ids=set())
    write_sarif(parent, reports)
    lines = ["## Jobs\n", jobs_summary, "\n## Findings\n"]
    if not reports:
        lines.append("No validated findings.\n")
    lines.extend(
        f"- `{report.get('id')}` {str(report.get('severity', '')).upper()} "
        f"{report.get('title', '')}\n"
        for report in reports
    )
    write_executive_report(parent, "".join(lines))


@dataclass(frozen=True)
class IsolationPlan:
    sequential: bool
    worker_cwd: Path
    worktree: Path | None


@dataclass(frozen=True)
class JobResult:
    job_id: str
    exit_code: int
    timed_out: bool


def first_local_path(targets_info: list[dict[str, Any]]) -> Path | None:
    for item in targets_info:
        if item.get("type") == "local_code":
            raw = item.get("details", {}).get("target_path")
            if raw:
                return Path(raw)
    return None


def plan_isolation(
    agent: str,
    job_id: str,
    local_path: Path | None,
    original_cwd: Path,
    tmp: Path,
    *,
    is_git: bool,
) -> IsolationPlan:
    if agent == "cursor":
        return IsolationPlan(
            sequential=True,
            worker_cwd=local_path or original_cwd,
            worktree=None,
        )
    if local_path is None:
        return IsolationPlan(sequential=False, worker_cwd=original_cwd, worktree=None)
    if not is_git:
        return IsolationPlan(sequential=True, worker_cwd=local_path, worktree=None)
    if agent == "codex":
        tree = tmp / job_id
        return IsolationPlan(sequential=False, worker_cwd=tree, worktree=tree)
    return IsolationPlan(sequential=False, worker_cwd=local_path, worktree=None)


def codex_worktree_argv(path: Path) -> list[str]:
    return ["git", "worktree", "add", "--detach", str(path), "HEAD"]


def audit_exit_code(
    results: Sequence[JobResult],
    finding_count: int,
    walk_incomplete: bool = False,
) -> int:
    if finding_count > 0:
        return 2
    if walk_incomplete:
        return 1
    if results and all(item.exit_code != 0 for item in results):
        return 1
    return 0


def worker_prompt(
    job: AuditJob,
    targets_info: list[dict[str, Any]],
    instruction: str,
    *,
    auth: AuditAuth | None = None,
) -> str:
    target_lines = "\n".join(
        f"- {item.get('original')} ({item.get('type')})" for item in targets_info
    )
    skills = ", ".join(job.skills)
    extra = f"\nAdditional instruction:\n{instruction}\n" if instruction else ""
    auth_text = ""
    if auth is not None and auth.has_auth():
        auth_names = ", ".join(auth.to_env())
        auth_text = (
            "\nAuthenticated context is available through these environment variables only: "
            f"{auth_names}. Use them when testing authenticated coverage. Do not print, log, "
            "or file the secret values.\n"
        )
    return (
        f"You are specialist {job.title} for this Strix audit.\n"
        f"Targets:\n{target_lines}\n"
        f"load_skill each of: {skills}\n"
        f"{job.task}\n"
        f"{auth_text}"
        "File only validated findings with create_vulnerability_report.\n"
        "Coverage todos are not seeded. Do not try to cover every vuln class.\n"
        "Do not spawn sub-agents / Task tools / extra CLI agents.\n"
        f"{extra}"
        "When finished, print AUDIT_JOB_DONE and exit 0.\n"
    )


def targets_info_for_audit(args: Any) -> list[dict[str, Any]]:
    targets_info: list[dict[str, Any]] = []
    targets = list(args.target or [])
    for target_list_path in args.target_list or []:
        targets.extend(read_target_list_file(target_list_path))

    for target in targets:
        try:
            target_type, target_dict = infer_target_type(target)
        except ValueError as exc:
            raise ValueError(f"Invalid target '{target}': {exc}") from None

        display_target = (
            target_dict.get("target_path", target) if target_type == "local_code" else target
        )
        if target_type == "api_spec":
            _resolve_api_spec(target, target_dict)

        targets_info.append(
            {"type": target_type, "details": target_dict, "original": display_target}
        )

    targets_info = dedupe_local_targets(targets_info)
    assign_workspace_subdirs(targets_info)
    return targets_info


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


_live_procs: list[subprocess.Popen[bytes]] = []
_interrupted = threading.Event()


def _kill_live_processes() -> None:
    for proc in _live_procs.copy():
        if proc.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)


def run_jobs(  # noqa: PLR0915
    jobs: Sequence[AuditJob],
    *,
    agent: str,
    binary: str,
    targets_info: list[dict[str, Any]],
    original_cwd: Path,
    parent: Path,
    instruction: str,
    max_workers: int,
    timeout: int,
    auth: AuditAuth | None = None,
) -> tuple[list[JobResult], int]:
    _interrupted.clear()
    local = first_local_path(targets_info)
    git = bool(local and is_git_repo(local))
    worktree_root = (
        Path(tempfile.mkdtemp(prefix="strix-audit-")) if agent == "codex" and git else None
    )
    tmp = worktree_root or original_cwd
    added_worktrees: list[Path] = []
    plans = {
        job.id: plan_isolation(
            agent,
            job.id,
            local,
            original_cwd,
            tmp,
            is_git=git,
        )
        for job in jobs
    }
    worker_run_base = parent.relative_to(original_cwd / "strix_runs").as_posix()

    def run_job(job: AuditJob) -> JobResult:  # noqa: PLR0911, PLR0912, PLR0915
        if job.id == "harvest":
            return JobResult(job.id, 0, timed_out=False)
        if _interrupted.is_set():
            return JobResult(job.id, 1, timed_out=False)
        plan = plans[job.id]
        cursor_path = plan.worker_cwd / ".cursor" / "mcp.json"
        cursor_backup = cursor_path.with_name(".mcp.json.strix-audit.bak")
        restore_cursor = False
        cursor_config_touched = False
        proc: subprocess.Popen[bytes] | None = None
        try:
            if plan.worktree:
                subprocess.run(  # noqa: S603
                    codex_worktree_argv(plan.worktree),
                    cwd=local or original_cwd,
                    check=True,
                )
                added_worktrees.append(plan.worktree)
                if _interrupted.is_set():
                    return JobResult(job.id, 1, timed_out=False)

            worker_dir = parent / "workers" / job.id
            worker_dir.mkdir(parents=True, exist_ok=True)
            worker_run_name = f"{worker_run_base}/workers/{job.id}"
            mcp = mcp_argv(str(original_cwd), worker_run_name)
            mcp_config = write_mcp_config_json(sys.executable, mcp[1:])
            mcp_path = worker_dir / "mcp.json"
            mcp_path.write_text(json.dumps(mcp_config, indent=2), encoding="utf-8")

            prompt = worker_prompt(job, targets_info, instruction, auth=auth)
            worker_env = os.environ.copy()
            if auth is not None:
                worker_env.update(auth.to_env())
            if agent == "claude":
                argv = claude_argv(
                    binary,
                    prompt,
                    mcp_path,
                    worktree_name=f"strix-audit-{job.id}" if git else None,
                )
            elif agent == "cursor":
                cursor_path.parent.mkdir(parents=True, exist_ok=True)
                if cursor_path.exists():
                    shutil.copy2(cursor_path, cursor_backup)
                    restore_cursor = True
                cursor_config_touched = True
                cursor_path.write_text(json.dumps(mcp_config, indent=2), encoding="utf-8")
                argv = cursor_argv(binary, prompt, plan.worker_cwd)
            else:
                argv = codex_argv(
                    binary,
                    prompt,
                    plan.worker_cwd,
                    str(original_cwd),
                    worker_run_name,
                )

            proc = subprocess.Popen(  # noqa: S603
                argv,
                cwd=plan.worker_cwd,
                env=worker_env,
                start_new_session=True,
            )
            _live_procs.append(proc)
            if _interrupted.is_set():
                return JobResult(job.id, 1, timed_out=False)
            try:
                proc.communicate(timeout=timeout)
                return JobResult(job.id, proc.returncode, timed_out=False)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                return JobResult(job.id, 1, timed_out=True)
        except (OSError, subprocess.SubprocessError):
            logger.exception("audit worker %s failed to start", job.id)
            _interrupted.set()
            _kill_live_processes()
            return JobResult(job.id, 1, timed_out=False)
        finally:
            if proc is not None and proc.poll() is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            if proc in _live_procs:
                _live_procs.remove(proc)
            if cursor_config_touched:
                if restore_cursor:
                    shutil.move(cursor_backup, cursor_path)
                else:
                    cursor_path.unlink(missing_ok=True)

    try:
        if any(plan.sequential for plan in plans.values()):
            results = [run_job(job) for job in jobs]
        else:
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            try:
                futures = [executor.submit(run_job, job) for job in jobs]
                results = [future.result() for future in futures]
            except KeyboardInterrupt:
                _interrupted.set()
                _kill_live_processes()
                raise
            finally:
                executor.shutdown(wait=True, cancel_futures=True)

        job_ids = [job.id for job in jobs]
        harvest_path = parent / "workers" / "harvest" / "vulnerabilities.json"
        if "harvest" not in job_ids and harvest_path.is_file():
            job_ids = ["harvest", *job_ids]
        reports = remint_ids(load_worker_reports(parent, job_ids))
        jobs_summary = "\n".join(
            f"{result.job_id}: exit {result.exit_code}"
            + (" (timed out)" if result.timed_out else "")
            for result in results
        )
        write_parent_reports(parent, reports, jobs_summary=jobs_summary)
        return results, len(reports)
    except KeyboardInterrupt:
        _interrupted.set()
        _kill_live_processes()
        raise
    finally:
        for path in added_worktrees:
            subprocess.run(  # noqa: S603
                ["git", "worktree", "remove", "--force", str(path)],  # noqa: S607
                cwd=local or original_cwd,
                check=False,
            )
        if worktree_root is not None:
            shutil.rmtree(worktree_root, ignore_errors=True)

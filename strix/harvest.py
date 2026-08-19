"""Deterministic domain harvest: expand hosts, ingest specs, walk unauth."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from strix.audit import FetchResult, _default_fetcher
from strix.core.paths import runtime_state_dir
from strix.interface.utils import infer_target_type
from strix.report.state import get_global_report_state
from strix.tools.attack_surface import tools as attack_surface
from strix.tools.attack_surface.tools import (
    _list_attack_surface_impl,
    _record_endpoint_impl,
    hydrate_attack_surface_from_disk,
)
from strix.tools.openapi_import.tools import _import_openapi_impl


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_HOST_RE = re.compile(
    r"(?:https?:)?//([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)",
    re.I,
)
_MAX_HOSTS = 200
_WALK_WORKERS = 10
_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "traceback",
    "sqlalchemy",
    "psycopg",
    "operationalerror",
    "internal server error",
    "postgresql",
)
_SPEC_PATHS = (
    "openapi.json",
    "docs",
    "redoc",
    ".well-known/mcp.json",
    ".well-known/oauth-authorization-server",
    "api/v1/tools",
)
_CRAWL_PATHS = ("robots.txt", "sitemap.xml", "llms.txt")
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

Fetcher = Callable[..., FetchResult]
Requester = Callable[[str, str], tuple[int, str]]
NameLookup = Callable[[str], list[str]]


@dataclass(frozen=True)
class HostRecord:
    url: str
    hostname: str
    live: bool
    status: int | None
    server: str | None
    fingerprints: tuple[str, ...]
    source: str
    probed: bool

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprints"] = list(self.fingerprints)
        return data


@dataclass(frozen=True)
class WalkResult:
    endpoint_id: str
    method: str
    url: str
    status: int
    classification: str
    reason: str
    body_preview: str


@dataclass(frozen=True)
class HarvestResult:
    hosts: list[HostRecord]
    walked: int
    candidates: int
    imported: int


def registrable_domain(host: str) -> str:
    # ponytail: last two labels only; no PSL. Upgrade: publicsuffixlist if we
    # need .co.uk / .com.au correctness.
    host = host.lower().rstrip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _brand_label(host: str) -> str:
    return registrable_domain(host).split(".")[0]


def related_apex_www(host: str) -> set[str]:
    apex = registrable_domain(host)
    return {host.lower().rstrip("."), apex, f"www.{apex}"}


def extract_linked_hosts(text: str, seed_host: str) -> set[str]:
    seed_reg = registrable_domain(seed_host)
    seed_brand = _brand_label(seed_host)
    found: set[str] = set()
    for match in _HOST_RE.finditer(text or ""):
        host = match.group(1).lower().rstrip(".")
        if host == seed_host.lower():
            continue
        host_reg = registrable_domain(host)
        if host_reg == seed_reg or _brand_label(host) == seed_brand:
            found.add(host)
    return found


def _https(host: str) -> str:
    return f"https://{host}/"


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _safe_fetch(fetch: Fetcher, url: str) -> FetchResult:
    try:
        result = fetch(url, {"User-Agent": "strix-harvest/1.0"})
    except TypeError:
        try:
            result = fetch(url)
        except (OSError, URLError, TimeoutError, ValueError):
            return FetchResult(url=url, status=0, headers={}, body="")
    except (OSError, URLError, TimeoutError, ValueError):
        return FetchResult(url=url, status=0, headers={}, body="")
    return result


def _fingerprints(result: FetchResult) -> tuple[str, ...]:
    headers = {k.lower(): v.lower() for k, v in result.headers.items()}
    body = result.body.lower()
    found: list[str] = []
    server = headers.get("server", "")
    if "uvicorn" in server or "fastapi" in body:
        found.append("fastapi")
    if "x-jenkins" in headers or "jenkins" in headers.get("x-jenkins", ""):
        found.append("jenkins")
    if "__next_data__" in body or "next.js" in headers.get("x-powered-by", ""):
        found.append("nextjs")
    if "wp-content" in body:
        found.append("wordpress")
    if "<listbucketresult" in body:
        found.append("gcs")
    return tuple(dict.fromkeys(found))


def default_sans_for(host: str) -> list[str]:
    try:
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((host, 443), timeout=5) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            cert = ssock.getpeercert() or {}
            return [
                item[1].lower()
                for item in cert.get("subjectAltName") or ()
                if (
                    isinstance(item, tuple)
                    and len(item) == 2
                    and item[0] == "DNS"
                    and isinstance(item[1], str)
                )
            ]
    except OSError:
        return []


def default_crt_names_for(reg: str) -> list[str]:
    url = f"https://crt.sh/?q=%.{reg}&output=json"
    result = _safe_fetch(_default_fetcher, url)
    if result.status != 200 or not result.body.strip():
        return []
    try:
        rows = json.loads(result.body)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw = row.get("name_value")
        if not isinstance(raw, str):
            continue
        for part in raw.split("\n"):
            name = part.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and registrable_domain(name) == reg:
                names.append(name)
        if len(names) >= 50:
            break
    return list(dict.fromkeys(names))


def expand_hosts(  # noqa: PLR0912
    seed_urls: Sequence[str],
    *,
    fetch: Fetcher | None = None,
    sans_for: NameLookup | None = None,
    crt_names_for: NameLookup | None = None,
) -> list[HostRecord]:
    resolved_fetch = fetch or _default_fetcher
    resolved_sans = sans_for or default_sans_for
    resolved_crt = crt_names_for or default_crt_names_for
    seeds = [url for url in seed_urls if urlparse(url).scheme in {"http", "https"}]
    if not seeds:
        return []
    seed_host = _hostname(seeds[0])
    seed_reg = registrable_domain(seed_host)
    pending: list[tuple[str, str]] = []
    seen: set[str] = set()
    sources: dict[str, str] = {}
    in_scope = {seed_reg}

    def enqueue(host: str, source: str) -> None:
        host = host.lower().rstrip(".")
        if not host or host in sources:
            return
        sources[host] = source
        pending.append((host, source))
        in_scope.add(registrable_domain(host))

    for url in seeds:
        host = _hostname(url)
        if host:
            enqueue(host, "seed")
            for related in related_apex_www(host):
                enqueue(related, "apex" if related != host else "seed")

    records: dict[str, HostRecord] = {}
    while pending and len(records) < _MAX_HOSTS:
        host, source = pending.pop(0)
        if host in seen:
            continue
        seen.add(host)
        url = _https(host)
        result = _safe_fetch(resolved_fetch, url)
        live = result.status > 0
        records[host] = HostRecord(
            url=url,
            hostname=host,
            live=live,
            status=result.status or None,
            server=result.headers.get("server") or result.headers.get("Server"),
            fingerprints=_fingerprints(result),
            source=sources.get(host, source),
            probed=True,
        )
        if not live:
            continue
        blobs = [result.body]
        for extra in _CRAWL_PATHS:
            extra_result = _safe_fetch(resolved_fetch, urljoin(url, extra))
            if extra_result.status > 0 and extra_result.body:
                blobs.append(extra_result.body)
        for blob in blobs:
            for linked in extract_linked_hosts(blob, seed_host):
                enqueue(linked, "html")
        if registrable_domain(host) in in_scope:
            for name in resolved_sans(host):
                if registrable_domain(name) in in_scope or _brand_label(name) == _brand_label(
                    seed_host
                ):
                    enqueue(name, "san")
            for name in resolved_crt(registrable_domain(host)):
                if registrable_domain(name) in in_scope:
                    enqueue(name, "crt")

    return list(records.values())


def persist_hosts(path: Path, hosts: Sequence[HostRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"hosts": [host.to_dict() for host in hosts]}, indent=2),
        encoding="utf-8",
    )


def load_hosts(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    hosts = data.get("hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        return []
    return [item for item in hosts if isinstance(item, dict)]


def ingest_openapi(spec: str) -> dict[str, Any]:
    return _import_openapi_impl(spec=spec)


def expand_tool_catalog(
    names: Sequence[str],
    path_template: str = "/api/v1/tools/{tool_name}/execute",
) -> int:
    added = 0
    for name in names:
        if not name or not str(name).strip():
            continue
        path = path_template.replace("{tool_name}", str(name).strip())
        result = _record_endpoint_impl(
            path=path,
            method="POST",
            notes=f"expanded from tool catalog: {name}",
        )
        if result.get("success"):
            added += 1
    return added


def tool_names_from_catalog(raw: str) -> list[str]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        items: Any = data
    elif isinstance(data, dict):
        items = data.get("tools") or data.get("data") or data.get("items") or []
    else:
        return []
    if not isinstance(items, list):
        return []
    names: list[str] = []
    for item in items:
        if isinstance(item, str) and item.strip():
            names.append(item.strip())
        elif isinstance(item, dict):
            name = item.get("name") or item.get("tool_name") or item.get("id")
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
    return list(dict.fromkeys(names))


def classify_response(status: int, body: str) -> tuple[str, str]:  # noqa: PLR0911
    if status in {401, 403}:
        return "auth_enforced", "auth"
    if status in {0, 404}:
        return "skip", "not_found_or_timeout"
    if 200 <= status < 300:
        if body.strip():
            lowered = body.lower()
            leak_keys = ("schema", "clerk", "table")
            reason = "unauth_data" if any(key in lowered for key in leak_keys) else "unauth_2xx"
            return "leak_candidate", reason
        return "skip", "empty_2xx"
    if status >= 500:
        lowered = body.lower()
        if any(marker in lowered for marker in _TRACE_MARKERS):
            return "leak_candidate", "unauth_5xx"
        return "skip", "5xx"
    return "skip", "other"


def endpoint_url(base_url: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def default_request(method: str, url: str) -> tuple[int, str]:
    headers = {"User-Agent": "strix-harvest/1.0"}
    data = None
    if method.upper() not in _SAFE_METHODS:
        headers["Content-Type"] = "application/json"
        data = b"{}"
    request = Request(url, data=data, headers=headers, method=method.upper())  # noqa: S310
    try:
        with urlopen(request, timeout=8) as response:  # noqa: S310
            raw = response.read(64_000)
            return int(getattr(response, "status", 0) or 0), raw.decode("utf-8", errors="replace")
    except HTTPError as exc:
        raw = exc.read(64_000)
        return exc.code, raw.decode("utf-8", errors="replace")
    except (OSError, URLError, TimeoutError, ValueError):
        return 0, ""


def write_walk_jsonl(path: Path, rows: Sequence[dict[str, Any] | WalkResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            payload = asdict(row) if isinstance(row, WalkResult) else row
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


def walk_unauth(
    endpoints: Sequence[dict[str, Any]],
    *,
    base_url: str,
    request: Requester | None = None,
    walk_path: Path | None = None,
    max_workers: int = _WALK_WORKERS,
) -> list[WalkResult]:
    resolved = request or default_request

    def probe(endpoint: dict[str, Any]) -> WalkResult:
        method = str(endpoint.get("method") or "GET").upper()
        path = str(endpoint.get("path") or "")
        url = endpoint_url(base_url, path)
        status, body = resolved(method, url)
        kind, reason = classify_response(status, body)
        return WalkResult(
            endpoint_id=str(endpoint.get("endpoint_id") or f"{method} {path}"),
            method=method,
            url=url,
            status=status,
            classification=kind,
            reason=reason,
            body_preview=body,
        )

    results: list[WalkResult] = []
    if not endpoints:
        if walk_path is not None:
            write_walk_jsonl(walk_path, [])
        return results
    workers = max(1, min(max_workers, len(endpoints)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, endpoint) for endpoint in endpoints]
        results = [future.result() for future in futures]
    if walk_path is not None:
        write_walk_jsonl(walk_path, results)
    return results


def group_leak_candidates(rows: Sequence[WalkResult]) -> list[dict[str, Any]]:
    tools: dict[str, list[WalkResult]] = {}
    grouped: list[dict[str, Any]] = []
    for row in rows:
        if row.classification != "leak_candidate":
            continue
        if "/tools/" in row.url and row.url.rstrip("/").endswith("/execute"):
            tools.setdefault(row.body_preview, []).append(row)
            continue
        grouped.append(_group_row(row, count=1))
    grouped.extend(_group_row(items[0], count=len(items)) for items in tools.values())
    return grouped


def _group_row(row: WalkResult, *, count: int) -> dict[str, Any]:
    return {
        "endpoint_id": row.endpoint_id,
        "method": row.method,
        "url": row.url,
        "status": row.status,
        "reason": row.reason,
        "body_preview": row.body_preview,
        "count": count,
    }


def _finding_reports(groups: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    reports: list[dict[str, Any]] = []
    for index, group in enumerate(groups, start=1):
        count = int(group.get("count") or 1)
        title = (
            f"Unauthenticated {group.get('method')} {group.get('url')} leaked data"
            if count == 1
            else f"{count} unauthenticated tool executes returned the same body"
        )
        reports.append(
            {
                "id": f"vuln-{index:04d}",
                "title": title,
                "severity": "medium",
                "timestamp": now,
                "description": (
                    f"{group.get('method')} {group.get('url')} returned HTTP {group.get('status')} "
                    f"without credentials ({group.get('reason')})."
                ),
                "endpoint": group.get("url"),
                "method": group.get("method"),
                "evidence": str(group.get("body_preview") or ""),
                "finding_class": "dynamic",
                "validated": True,
            }
        )
    return reports


def file_harvest_findings(parent: Path, groups: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    reports = _finding_reports(groups)
    path = parent / "workers" / "harvest" / "vulnerabilities.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(reports, indent=2), encoding="utf-8")
    state = get_global_report_state()
    if state is not None:
        for report in reports:
            state.add_vulnerability_report(
                title=str(report["title"]),
                severity=str(report["severity"]),
                description=str(report.get("description") or ""),
                endpoint=str(report.get("endpoint") or "") or None,
                method=str(report.get("method") or "") or None,
                evidence=str(report.get("evidence") or "") or None,
                finding_class="dynamic",
                validated=True,
            )
    return reports


def targets_from_hosts(
    hosts: Sequence[HostRecord],
    existing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out = list(existing)
    seen = {
        (urlparse(str(item.get("details", {}).get("target_url") or "")).hostname or "").lower()
        for item in existing
    }
    for host in hosts:
        if not host.live or host.hostname in seen:
            continue
        target_type, details = infer_target_type(host.url)
        out.append({"type": target_type, "details": details, "original": host.url})
        seen.add(host.hostname)
    return out


def _record_fingerprint_endpoints(host: HostRecord, result: FetchResult) -> None:
    headers = {k.lower(): v for k, v in result.headers.items()}
    if "x-jenkins" in headers or "jenkins" in host.fingerprints:
        _record_endpoint_impl(path=host.url, method="GET", notes="jenkins fingerprint")
    if "<ListBucketResult" in result.body or "gcs" in host.fingerprints:
        _record_endpoint_impl(path=host.url, method="GET", notes="bucket listing")


def ingest_host_specs(host: HostRecord, *, fetch: Fetcher) -> int:
    imported = 0
    root = _safe_fetch(fetch, host.url)
    _record_fingerprint_endpoints(host, root)
    for rel in _SPEC_PATHS:
        result = _safe_fetch(fetch, urljoin(host.url, rel))
        if result.status != 200 or not result.body.strip():
            continue
        if rel.endswith("openapi.json") or '"openapi"' in result.body[:200]:
            report = ingest_openapi(result.body)
            if report.get("success"):
                imported += int(report.get("imported_count") or 0)
        if rel.endswith(("api/v1/tools", "mcp.json")):
            imported += expand_tool_catalog(tool_names_from_catalog(result.body))
    return imported


def _ensure_surface(parent: Path) -> None:
    if attack_surface._store_path is None:
        state_dir = runtime_state_dir(parent)
        state_dir.mkdir(parents=True, exist_ok=True)
        hydrate_attack_surface_from_disk(state_dir)


def _api_base(hosts: Sequence[HostRecord], seeds: Sequence[str]) -> str:
    for host in hosts:
        if host.live and "fastapi" in host.fingerprints:
            return host.url
    for host in hosts:
        if host.live:
            return host.url
    if seeds:
        return seeds[0]
    return ""


def discover_assets(
    seed_urls: Sequence[str],
    parent: Path,
    *,
    fetch: Fetcher | None = None,
    sans_for: NameLookup | None = None,
    crt_names_for: NameLookup | None = None,
) -> tuple[list[HostRecord], int]:
    parent.mkdir(parents=True, exist_ok=True)
    _ensure_surface(parent)
    resolved_fetch = fetch or _default_fetcher
    hosts = expand_hosts(
        seed_urls,
        fetch=resolved_fetch,
        sans_for=sans_for,
        crt_names_for=crt_names_for,
    )
    persist_hosts(parent / "hosts.json", hosts)
    imported = 0
    for host in hosts:
        if host.live:
            imported += ingest_host_specs(host, fetch=resolved_fetch)
    return hosts, imported


def run_harvest(
    seed_urls: Sequence[str],
    parent: Path,
    *,
    fetch: Fetcher | None = None,
    request: Requester | None = None,
    sans_for: NameLookup | None = None,
    crt_names_for: NameLookup | None = None,
) -> HarvestResult:
    hosts, imported = discover_assets(
        seed_urls,
        parent,
        fetch=fetch,
        sans_for=sans_for,
        crt_names_for=crt_names_for,
    )
    endpoints = _list_attack_surface_impl()["endpoints"]
    results = walk_unauth(
        endpoints,
        base_url=_api_base(hosts, seed_urls),
        request=request,
        walk_path=parent / "walk.jsonl",
    )
    groups = group_leak_candidates(results)
    file_harvest_findings(parent, groups)
    return HarvestResult(
        hosts=hosts,
        walked=len(results),
        candidates=len(groups),
        imported=imported,
    )


def _walked_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    ids: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("endpoint_id"):
            ids.add(str(row["endpoint_id"]))
    return ids


def _surface_endpoint_ids(run_dir: Path) -> list[str]:
    expected = runtime_state_dir(run_dir) / "attack_surface.json"
    if attack_surface._store_path == expected:
        live = _list_attack_surface_impl().get("endpoints") or []
        return [str(item.get("endpoint_id")) for item in live if item.get("endpoint_id")]
    if not expected.is_file():
        return []
    try:
        data = json.loads(expected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    endpoints = data.get("endpoints") if isinstance(data, dict) else None
    if isinstance(endpoints, dict):
        return list(endpoints)
    return []


def current_run_dir() -> Path | None:
    state = get_global_report_state()
    if state is not None:
        return state.get_run_dir()
    return None


def walk_coverage(run_dir: Path | None = None) -> dict[str, Any]:
    resolved = run_dir or current_run_dir()
    if resolved is None:
        return {
            "incomplete": False,
            "unwalked_endpoints": [],
            "unprobed_hosts": [],
        }
    endpoint_ids = _surface_endpoint_ids(resolved)
    walked = _walked_ids(resolved / "walk.jsonl")
    unwalked = [eid for eid in endpoint_ids if eid not in walked]
    unprobed = [
        str(host.get("hostname") or host.get("url"))
        for host in load_hosts(resolved / "hosts.json")
        if host.get("live") and not host.get("probed")
    ]
    return {
        "incomplete": bool(unwalked or unprobed),
        "unwalked_endpoints": unwalked,
        "unprobed_hosts": unprobed,
        "walked_count": len(walked),
        "endpoint_count": len(endpoint_ids),
    }

"""Auto-validation of findings — re-run a PoC and prove its claimed impact.

Before a finding is filed, ``validate_finding`` replays the exploit request
and decides whether the response *proves* the claim (for a data leak it
captures the actual leaked data as ``proof_excerpt``). Records are mirrored
to ``{state_dir}/validations.json``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.credentials.tools import _get_credential_impl
from strix.tools.http_replay.tools import _replay_impl


logger = logging.getLogger(__name__)


_validations_storage: dict[str, dict[str, Any]] = {}
_validations_lock = threading.RLock()
_validations_path: Path | None = None

_VALID_CLAIM_TYPES = ("data_leak", "reflection", "status_change", "auth_bypass", "generic")
_ACCESS_DENIED_STATUS = (401, 403)
_REPLAYS = 2
_PROOF_WINDOW = 100
_PROOF_EXCERPT_CAP = 400
_ID_GENERATION_ATTEMPTS = 1024


def hydrate_validations_from_disk(state_dir: Path) -> None:
    global _validations_path  # noqa: PLW0603
    _validations_path = state_dir / "validations.json"
    with _validations_lock:
        _validations_storage.clear()
        if not _validations_path.exists():
            return
        try:
            data = json.loads(_validations_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "validations.json at %s is unreadable; starting empty", _validations_path
            )
            return
        if not isinstance(data, dict):
            return
        _validations_storage.update(
            {
                vid: rec
                for vid, rec in data.items()
                if isinstance(vid, str) and isinstance(rec, dict)
            }
        )
        logger.info(
            "validations hydrated from %s (%d record(s))",
            _validations_path,
            len(_validations_storage),
        )


def _persist() -> None:
    path = _validations_path
    if path is None:
        return
    try:
        payload = json.dumps(_validations_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _validations_lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("validations persist to %s failed", path)


def _generate_id() -> str | None:
    for _ in range(_ID_GENERATION_ATTEMPTS):
        vid = uuid.uuid4().hex[:6]
        if vid not in _validations_storage:
            return vid
    return None


def get_validation(validation_id: str) -> dict[str, Any] | None:
    """Look up a persisted validation record by id (for the reporting module)."""
    with _validations_lock:
        rec = _validations_storage.get(validation_id)
        return dict(rec) if rec is not None else None


def _content_match(body: str, expect_contains: str | None, regex: re.Pattern[str] | None) -> bool:
    if expect_contains is not None and expect_contains in body:
        return True
    return bool(regex is not None and regex.search(body))


def _extract_proof(
    body: str, expect_contains: str | None, regex: re.Pattern[str] | None
) -> str | None:
    if regex is not None:
        match = regex.search(body)
        if match:
            return match.group(0)[:_PROOF_EXCERPT_CAP]
    if expect_contains is not None:
        idx = body.find(expect_contains)
        if idx != -1:
            start = max(0, idx - _PROOF_WINDOW)
            end = idx + len(expect_contains) + _PROOF_WINDOW
            return body[start:end][:_PROOF_EXCERPT_CAP]
    return None


def _signal_found(
    resp: dict[str, Any],
    expect_status: int | None,
    expect_contains: str | None,
    regex: re.Pattern[str] | None,
) -> bool:
    if not resp.get("success"):
        return False
    status_ok = expect_status is None or resp.get("status_code") == expect_status
    if expect_contains is None and regex is None:
        return status_ok  # status-only signal
    return status_ok and _content_match(resp.get("body") or "", expect_contains, regex)


def _validate_impl(  # noqa: PLR0911, PLR0912
    *,
    claim_type: str,
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout: int,
    allow_redirects: bool,
    expect_contains: str | None,
    expect_regex: str | None,
    expect_status: int | None,
    baseline_headers: dict[str, str] | None,
    baseline_no_auth: bool,
) -> dict[str, Any]:
    claim_type = (claim_type or "generic").strip().lower()
    if claim_type not in _VALID_CLAIM_TYPES:
        return {
            "validated": False,
            "error": (
                f"invalid claim_type {claim_type!r}; must be one of {list(_VALID_CLAIM_TYPES)}"
            ),
        }

    try:
        regex = re.compile(expect_regex) if expect_regex else None
    except re.error as exc:
        return {"validated": False, "error": f"invalid expect_regex: {exc}"}

    has_content_signal = expect_contains is not None or regex is not None
    has_any_signal = has_content_signal or expect_status is not None
    if claim_type != "generic" and not has_any_signal:
        return {
            "validated": False,
            "error": (
                "a non-generic claim requires at least one proof signal "
                "(expect_contains, expect_regex, or expect_status)"
            ),
        }
    if claim_type == "data_leak" and not has_content_signal:
        return {
            "validated": False,
            "error": "data_leak requires expect_contains or expect_regex (a sample of the data)",
        }

    replays = [
        _replay_impl(method, url, headers, body, timeout, allow_redirects) for _ in range(_REPLAYS)
    ]
    for resp in replays:
        if not resp.get("success"):
            return {
                "validated": False,
                "error": f"exploit request failed: {resp.get('error')}",
            }

    exploit_status = replays[0].get("status_code")
    signal_found = all(
        _signal_found(resp, expect_status, expect_contains, regex) for resp in replays
    )
    reproducible = signal_found  # both replays must show it (checked via all() above)
    proof_excerpt = (
        _extract_proof(replays[0].get("body") or "", expect_contains, regex)
        if signal_found
        else None
    )

    baseline_configured = baseline_no_auth or baseline_headers is not None
    unauthorized_confirmed = False
    baseline_public = False
    if baseline_configured:
        baseline = _replay_impl(method, url, baseline_headers, body, timeout, allow_redirects)
        if not baseline.get("success"):
            return {
                "validated": False,
                "error": f"baseline request failed: {baseline.get('error')}",
            }
        baseline_denied = baseline.get("status_code") in _ACCESS_DENIED_STATUS
        baseline_has_data = _content_match(baseline.get("body") or "", expect_contains, regex)
        unauthorized_confirmed = baseline_denied or not baseline_has_data
        baseline_public = baseline_has_data and not baseline_denied

    validated = (
        reproducible and signal_found and (unauthorized_confirmed or not baseline_configured)
    )

    if not signal_found:
        reason = "expected signal not found in the response — claim not proven"
    elif baseline_public:
        reason = "data is public / not access-controlled — same signal present without auth"
    elif validated:
        reason = f"signal reproduced across {_REPLAYS} replays"
        if baseline_configured:
            reason += "; absent for the unauthorized baseline"
    else:
        reason = "not validated"

    record: dict[str, Any] = {
        "claim_type": claim_type,
        "url": url,
        "method": method.upper(),
        "validated": validated,
        "reason": reason,
        "proof_excerpt": proof_excerpt,
        "exploit_status": exploit_status,
        "replays": _REPLAYS,
        "unauthorized_confirmed": unauthorized_confirmed,
        "created_at": datetime.now(UTC).isoformat(),
    }

    with _validations_lock:
        vid = _generate_id()
        if vid is None:
            return {"validated": False, "error": "failed to generate a unique validation id"}
        record["id"] = vid
        _validations_storage[vid] = record
        _persist()
    return record


@function_tool(timeout=120, strict_mode=False)
async def validate_finding(
    ctx: RunContextWrapper,
    method: str,
    url: str,
    claim_type: str = "generic",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 20,
    allow_redirects: bool = False,
    expect_contains: str | None = None,
    expect_regex: str | None = None,
    expect_status: int | None = None,
    baseline_headers: dict[str, str] | None = None,
    baseline_no_auth: bool = False,
) -> str:
    """Re-run an exploit PoC and prove it demonstrates the claimed impact.

    Sends the exploit request **twice** (reproducibility) and decides whether
    the response proves the claim. For a ``data_leak`` it captures the actual
    leaked data in ``proof_excerpt`` — that evidence is the point. Pass the
    returned ``id`` as ``validation_id`` to ``create_vulnerability_report``.

    Provide at least one proof signal (``data_leak`` requires
    ``expect_contains`` or ``expect_regex``). When a baseline is configured
    (``baseline_no_auth`` or ``baseline_headers``) the request is also sent
    without the exploit auth and the signal must be ABSENT there — proving the
    data is genuinely access-controlled, not public.

    Returns the full JSON record (``id``, ``validated``, ``reason``,
    ``proof_excerpt``, ``exploit_status``, ``replays``,
    ``unauthorized_confirmed``). Errors return ``{"validated": false,
    "error": ...}`` instead of raising.

    Args:
        method: HTTP method of the exploit request.
        url: Full exploit request URL.
        claim_type: ``data_leak`` / ``reflection`` / ``status_change`` /
            ``auth_bypass`` / ``generic`` (default ``generic``).
        headers: Exploit request headers (e.g. the victim/attacker auth).
        body: Optional raw request body.
        timeout: Request timeout in seconds (default 20).
        allow_redirects: Follow redirects (default False).
        expect_contains: Substring that must appear in the response body to
            prove impact (a sample of the leaked data, or the reflected payload).
        expect_regex: Regex alternative to ``expect_contains``.
        expect_status: Response status that proves the claim (e.g. 200 on a
            protected resource for auth_bypass).
        baseline_headers: Headers for the unauthorized baseline request.
        baseline_no_auth: When True, also send the request with no headers as
            the unauthorized baseline.
    """
    return json.dumps(
        await asyncio.to_thread(
            _validate_impl,
            claim_type=claim_type,
            method=method,
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
            allow_redirects=allow_redirects,
            expect_contains=expect_contains,
            expect_regex=expect_regex,
            expect_status=expect_status,
            baseline_headers=baseline_headers,
            baseline_no_auth=baseline_no_auth,
        ),
        ensure_ascii=False,
        default=str,
    )


def _retest_findings_impl(
    headers: dict[str, str] | None, credential_label: str | None
) -> dict[str, Any]:
    """Replay every validated finding's exploit and report still-open vs fixed.

    Uses each validation record's stored url + proof_excerpt as the signal.
    Records store no auth headers, so the caller supplies current auth
    (headers or a stored credential) — otherwise an authed endpoint would
    401 and look falsely fixed."""
    hdrs = dict(headers or {})
    if credential_label:
        cred = _get_credential_impl(credential_label)
        if not cred.get("success"):
            return {"success": False, "error": f"credential '{credential_label}' not found"}
        hdrs.setdefault("Authorization", cred.get("value") or "")

    with _validations_lock:
        records = [dict(r) for r in _validations_storage.values() if r.get("validated")]

    results: list[dict[str, Any]] = []
    counts = {"still_open": 0, "fixed": 0, "inconclusive": 0}
    for rec in records:
        url = rec.get("url")
        proof = rec.get("proof_excerpt")
        entry: dict[str, Any] = {"validation_id": rec.get("id"), "url": url}
        if not url or not proof:
            entry["status"] = "inconclusive"
            entry["reason"] = "no replayable url + proof signal stored"
        else:
            resp = _replay_impl(
                str(rec.get("method") or "GET"), url, hdrs or None, None, 15, allow_redirects=False
            )
            if not resp.get("success"):
                entry["status"] = "inconclusive"
                entry["reason"] = f"replay failed: {resp.get('error')}"
            else:
                still_open = _content_match(resp.get("body") or "", str(proof), None)
                entry["status"] = "still_open" if still_open else "fixed"
                entry["http_status"] = resp.get("status_code")
        counts[entry["status"]] += 1
        results.append(entry)
    return {"success": True, "retested": len(results), **counts, "results": results}


@function_tool(timeout=300, strict_mode=False)
async def retest_findings(
    ctx: RunContextWrapper,
    headers: dict[str, str] | None = None,
    credential_label: str | None = None,
) -> str:
    """Re-run every validated finding's exploit and report which are still open.

    For each validated finding, replays its stored exploit URL and checks
    whether the proven signal (``proof_excerpt``) still appears — marking it
    ``still_open`` or ``fixed``. Findings without a replayable url + proof are
    ``inconclusive`` (retest by hand). Because validation records don't store
    auth, pass current credentials so authed endpoints don't 401 and look
    falsely fixed. Only test authorized targets.

    Returns JSON with ``retested``, ``still_open``, ``fixed``, ``inconclusive``,
    and a per-finding ``results`` list.

    Args:
        headers: Headers applied to every replay (e.g. a fresh session cookie).
        credential_label: A ``store_credential`` label whose value is sent as
            ``Authorization`` on every replay (unless ``headers`` already sets it).
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_retest_findings_impl, headers, credential_label),
        ensure_ascii=False,
        default=str,
    )

"""``diff_response`` — compare two HTTP responses for injection signals."""

from __future__ import annotations

import difflib
import json
from typing import Any

from agents import RunContextWrapper, function_tool


_REFLECTION_CONTEXT_CHARS = 40
_LARGE_DELTA_CHARS = 512


def _reflection_info(payload_response: str, payload: str) -> dict[str, Any]:
    occurrences = payload_response.count(payload)
    info: dict[str, Any] = {"reflected": occurrences > 0, "occurrences": occurrences}
    if occurrences:
        idx = payload_response.find(payload)
        start = max(0, idx - _REFLECTION_CONTEXT_CHARS)
        end = idx + len(payload) + _REFLECTION_CONTEXT_CHARS
        info["context"] = payload_response[start:end]
    return info


def _diff_response_impl(
    baseline: str,
    payload_response: str,
    payload: str | None = None,
    baseline_status: int | None = None,
    payload_status: int | None = None,
) -> dict[str, Any]:
    baseline_lines = baseline.splitlines(keepends=True)
    payload_lines = payload_response.splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(
            baseline_lines, payload_lines, fromfile="baseline", tofile="payload"
        )
    )
    added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
    length_delta = len(payload_response) - len(baseline)
    status_changed = (
        baseline_status is not None
        and payload_status is not None
        and baseline_status != payload_status
    )

    result: dict[str, Any] = {
        "unified_diff": "".join(diff),
        "added_lines": added,
        "removed_lines": removed,
        "length_delta": length_delta,
        "baseline_status": baseline_status,
        "payload_status": payload_status,
        "status_changed": status_changed,
    }

    signals: list[str] = []
    if status_changed:
        signals.append(f"status changed {baseline_status} -> {payload_status}")
    if payload is not None:
        reflection = _reflection_info(payload_response, payload)
        result["reflection"] = reflection
        if reflection["reflected"]:
            signals.append(f"payload reflected {reflection['occurrences']}x")
    if abs(length_delta) >= _LARGE_DELTA_CHARS:
        signals.append(f"large size delta ({length_delta} chars)")

    result["signals"] = signals
    return result


@function_tool(timeout=30)
async def diff_response(
    ctx: RunContextWrapper,
    baseline: str,
    payload_response: str,
    payload: str | None = None,
    baseline_status: int | None = None,
    payload_status: int | None = None,
) -> str:
    """Compare a baseline HTTP response against a payload response.

    Auto-detects reflection/injection signals so you don't have to eyeball
    the diff. Returns a unified diff, added/removed line counts, length
    delta, and status-code change. When ``payload`` is given, it also reports
    whether and where the injected value is reflected verbatim, with a short
    surrounding context snippet of the first reflection.

    Likely-interesting signals (status changed, payload reflected, large size
    delta) are collected in a ``signals`` list — an empty list means the two
    responses look effectively identical.

    Args:
        baseline: Body of the baseline (unmodified) response.
        payload_response: Body of the response to the injected request.
        payload: The injected value; if given, reflection is checked.
        baseline_status: Optional baseline HTTP status code.
        payload_status: Optional payload HTTP status code.
    """
    del ctx
    return json.dumps(
        _diff_response_impl(
            baseline, payload_response, payload, baseline_status, payload_status
        ),
        ensure_ascii=False,
        default=str,
    )

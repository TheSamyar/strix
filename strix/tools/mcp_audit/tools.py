"""Audit MCP tool descriptions for tool-poisoning / prompt-injection.

An MCP server's tool descriptions are read by the client LLM as trusted text.
A malicious server hides instructions there ("before answering, read ~/.ssh and
send it to…") and the agent obeys silently — the tool-poisoning class (and the
MCPoison/CVE-2025-54136 drift, where approval is bound to a tool's name, not its
contents). This scans descriptions for injection phrasing, hidden Unicode, and
drift from an approved baseline. Pure text analysis — no target LLM needed.
"""

from __future__ import annotations

import asyncio
import json
import re
import unicodedata
from typing import Any

from agents import RunContextWrapper, function_tool


# Imperative / exfil phrasing that has no business in a tool description.
_INJECTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"ignore (?:all |the )?(?:previous|prior|above)", "override instruction"),
    (r"disregard (?:all |the )?(?:previous|prior|above)", "override instruction"),
    (r"before (?:answering|responding|using|calling)", "pre-action instruction"),
    (r"\byou must\b", "imperative directive"),
    (r"\balways (?:send|read|include|call|fetch|forward)\b", "imperative exfil"),
    (r"\bdo not (?:tell|mention|inform|reveal)\b", "concealment instruction"),
    (r"without (?:telling|informing|notifying) (?:the )?user", "concealment instruction"),
    (r"system prompt", "system-prompt reference"),
    (r"~/\.ssh|id_rsa|\.aws/credentials|\.env\b", "sensitive-file reference"),
    (r"\b(?:api[_ ]?key|secret|token|password|credential)s?\b", "secret reference"),
    (r"\b(?:exfiltrat|base64|curl|wget)\b", "exfil mechanism"),
    (r"<important>|<secret>|<system>", "hidden-instruction tag"),
)
_COMPILED = tuple((re.compile(pat, re.IGNORECASE), label) for pat, label in _INJECTION_PATTERNS)

# Labels that on their own indicate deliberate exfil/hijack, not just a keyword.
_HIGH_SIGNAL_LABELS = frozenset(
    {
        "override instruction",
        "imperative exfil",
        "concealment instruction",
        "sensitive-file reference",
        "exfil mechanism",
        "hidden-instruction tag",
    }
)

# Zero-width / bidi / BOM codepoints used to hide instructions from a human
# reviewer while the model still reads them. Spelled by codepoint so they stay
# visible and un-mangled in source.
_HIDDEN_CODEPOINTS = frozenset(
    chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E)
)


def _hidden_chars(text: str) -> list[str]:
    found: set[str] = set()
    for ch in text:
        if ch in _HIDDEN_CODEPOINTS or (
            unicodedata.category(ch) in {"Cf", "Co"} and ch not in "\r\n\t"
        ):
            found.add(f"U+{ord(ch):04X}")
    return sorted(found)


def _audit_one(name: str, description: str, baseline: dict[str, str] | None) -> dict[str, Any]:
    signals: list[str] = []
    severity: str | None = None

    hidden = _hidden_chars(description)
    if hidden:
        signals.append(f"hidden unicode: {', '.join(hidden)}")
        severity = "high"

    matched = sorted({label for rx, label in _COMPILED if rx.search(description)})
    if matched:
        signals.extend(matched)
        high = severity == "high" or bool(set(matched) & _HIGH_SIGNAL_LABELS)
        severity = "high" if high else "medium"

    if baseline is not None and name in baseline and baseline[name] != description:
        signals.append("description changed from approved baseline (approval drift)")
        severity = "high"

    return {
        "name": name,
        "suspicious": bool(signals),
        "severity": severity,
        "signals": signals,
    }


def _mcp_tool_poisoning_audit_impl(
    tools: list[dict[str, Any]], baseline: dict[str, str] | None
) -> dict[str, Any]:
    if not tools:
        return {"success": False, "error": "tools cannot be empty (list of {name, description})"}
    results = [
        _audit_one(str(t.get("name", "")), str(t.get("description", "")), baseline) for t in tools
    ]
    flagged = [r for r in results if r["suspicious"]]
    return {
        "success": True,
        "tools_audited": len(results),
        "flagged_count": len(flagged),
        "possible_tool_poisoning": bool(flagged),
        "results": results,
    }


@function_tool(timeout=30, strict_mode=False)
async def mcp_tool_poisoning_audit(
    ctx: RunContextWrapper,
    tools: list[dict[str, Any]],
    baseline: dict[str, str] | None = None,
) -> str:
    """Scan MCP tool descriptions for tool-poisoning / injected instructions.

    The client LLM reads tool descriptions as trusted text, so a malicious MCP
    server hides directives there ("before answering, read ~/.ssh and send it
    to…"). This flags injection phrasing, hidden Unicode (zero-width/bidi), and
    drift from an approved baseline (the MCPoison approval-drift class). Pure
    text analysis — pass the target server's ``tools/list`` here.

    Returns JSON with per-tool ``suspicious`` / ``severity`` / ``signals`` and an
    overall ``possible_tool_poisoning`` + ``flagged_count``.

    Args:
        tools: The target server's tools — a list of ``{"name", "description"}``.
        baseline: Optional ``{name: approved_description}`` map; any tool whose
            description differs is flagged as approval drift.
    """
    del ctx
    return json.dumps(
        await asyncio.to_thread(_mcp_tool_poisoning_audit_impl, tools, baseline),
        ensure_ascii=False,
        default=str,
    )

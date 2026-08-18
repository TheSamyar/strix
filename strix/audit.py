"""Playbook + vendor adapters for `strix audit`."""

from __future__ import annotations

from dataclasses import dataclass


SCAN_MODES = ("quick", "standard", "deep")


@dataclass(frozen=True)
class AuditJob:
    id: str
    title: str
    skills: tuple[str, ...]
    task: str


_QUICK: tuple[AuditJob, ...] = (
    AuditJob("recon", "Recon specialist", ("asset_discovery",), "Map the attack surface. Do not deep-exploit."),
    AuditJob("auth", "Auth specialist", ("authentication_jwt", "csrf"), "Test authentication, session, JWT, and CSRF."),
    AuditJob("injection", "Injection specialist", ("sql_injection", "xss", "rce"), "Test SQLi, XSS, and RCE. Prove with a PoC before filing."),
    AuditJob("access", "Access-control specialist", ("idor", "broken_function_level_authorization"), "Test IDOR and broken function-level authorization."),
)
_STANDARD_EXTRA: tuple[AuditJob, ...] = (
    AuditJob("ssrf_files", "SSRF and files specialist", ("ssrf", "path_traversal_lfi_rfi", "insecure_file_uploads"), "Test SSRF, path traversal, and file uploads."),
    AuditJob("secrets_deps", "Secrets and deps specialist", ("information_disclosure", "dependency_cve_scanning"), "Find secrets and known-CVE dependencies."),
)
_DEEP_EXTRA: tuple[AuditJob, ...] = (
    AuditJob("logic", "Logic specialist", ("business_logic", "race_conditions"), "Test business logic and race conditions."),
    AuditJob("deser_ssti", "Deser/SSTI specialist", ("insecure_deserialization", "ssti"), "Test insecure deserialization and SSTI."),
)


def jobs_for_mode(mode: str) -> tuple[AuditJob, ...]:
    if mode == "quick":
        return _QUICK
    if mode == "standard":
        return _QUICK + _STANDARD_EXTRA
    if mode == "deep":
        return _QUICK + _STANDARD_EXTRA + _DEEP_EXTRA
    raise ValueError(f"unknown scan-mode {mode!r}; expected one of {SCAN_MODES}")

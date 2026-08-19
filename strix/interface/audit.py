"""`strix audit` — hire Claude / Cursor Agent / Codex as playbook workers."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from strix.audit import (
    AGENT_HINTS,
    SCAN_MODES,
    SITE_PROFILES,
    _interrupted,
    _kill_live_processes,
    audit_exit_code,
    auth_from_args,
    detect_site_profile,
    jobs_for_mode,
    missing_recommended_tools,
    resolve_agent,
    run_jobs,
    targets_info_for_audit,
    web_target_urls,
)
from strix.core.paths import run_dir_for
from strix.interface.utils import generate_run_name
from strix.report.writer import write_run_record


def parse_audit_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="strix audit",
        description="Run a playbook of specialist coding-agent workers. No Docker.",
    )
    parser.add_argument("-t", "--target", action="append", dest="target")
    parser.add_argument("--target-list", action="append", dest="target_list")
    parser.add_argument("--agent", choices=("claude", "cursor", "codex"))
    parser.add_argument("-m", "--scan-mode", choices=SCAN_MODES, default="quick")
    parser.add_argument("--site-profile", choices=SITE_PROFILES, default="auto")
    parser.add_argument("--run-name")
    parser.add_argument("--max-workers", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--instruction", default="")
    parser.add_argument("--instruction-file")
    parser.add_argument("--auth-cookie")
    parser.add_argument("--auth-header", action="append", dest="auth_header")
    parser.add_argument("--login-url")
    parser.add_argument("--login-username")
    parser.add_argument("--login-password")
    args = parser.parse_args(argv)
    if not args.target and not args.target_list:
        parser.error("the following arguments are required: -t/--target")
    if args.run_name and (Path(args.run_name).is_absolute() or ".." in args.run_name):
        parser.error("--run-name must be relative and must not contain ..")
    if args.max_workers < 1:
        parser.error("--max-workers must be >= 1")
    if args.timeout < 1:
        parser.error("--timeout must be >= 1")
    if args.instruction_file:
        args.instruction = (args.instruction + "\n" if args.instruction else "") + Path(
            args.instruction_file
        ).read_text(encoding="utf-8")
    return args


def run_audit(argv: list[str]) -> int:
    args = parse_audit_args(argv)
    try:
        auth = auth_from_args(args)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    try:
        targets_info = targets_info_for_audit(args)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    if not targets_info:
        sys.stderr.write("No targets.\n")
        return 1
    try:
        agent, binary = resolve_agent(args.agent, path_lookup=shutil.which)
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        if args.agent:
            sys.stderr.write(f"{AGENT_HINTS.get(args.agent, '')}\n")
        else:
            sys.stderr.write("\n".join(AGENT_HINTS.values()) + "\n")
        return 1

    run_name = args.run_name or generate_run_name(targets_info)
    original_cwd = Path.cwd()
    parent = run_dir_for(run_name, cwd=original_cwd)
    parent.mkdir(parents=True, exist_ok=True)
    profile_detection = detect_site_profile(
        web_target_urls(targets_info),
        args.site_profile,
        auth=auth,
    )
    (parent / "site_profile.json").write_text(
        json.dumps(profile_detection.to_dict(), indent=2),
        encoding="utf-8",
    )
    missing_tools = missing_recommended_tools(
        profile_detection.resolved,
        path_lookup=shutil.which,
    )
    if missing_tools:
        sys.stderr.write(
            "Warning: missing recommended live-audit tool(s) for "
            f"{profile_detection.resolved}: {', '.join(missing_tools)}. "
            "Continuing; coverage may be reduced.\n"
        )
    try:
        results, finding_count = run_jobs(
            jobs_for_mode(args.scan_mode, site_profile=profile_detection.resolved),
            agent=agent,
            binary=binary,
            targets_info=targets_info,
            original_cwd=original_cwd,
            parent=parent,
            instruction=args.instruction or "",
            max_workers=args.max_workers,
            timeout=args.timeout,
            auth=auth,
        )
    except KeyboardInterrupt:
        _interrupted.set()
        _kill_live_processes()
        write_run_record(parent, {"status": "error", "agent": agent})
        return 1

    write_run_record(
        parent,
        {
            "status": "completed",
            "agent": agent,
            "scan_mode": args.scan_mode,
            "site_profile": profile_detection.resolved,
            "site_profile_requested": args.site_profile,
            "auth": auth.to_redacted_dict(),
            "scanner_warnings": list(missing_tools),
            "jobs": [
                {"id": result.job_id, "exit": result.exit_code, "timed_out": result.timed_out}
                for result in results
            ],
            "finding_count": finding_count,
        },
    )
    return audit_exit_code(results, finding_count)

"""`strix audit` — hire Claude / Cursor Agent / Codex as playbook workers."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from strix.audit import (
    AGENT_HINTS,
    SCAN_MODES,
    _interrupted,
    _kill_live_processes,
    audit_exit_code,
    jobs_for_mode,
    resolve_agent,
    run_jobs,
    targets_info_for_audit,
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
    parser.add_argument("--run-name")
    parser.add_argument("--max-workers", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--instruction", default="")
    parser.add_argument("--instruction-file")
    args = parser.parse_args(argv)
    if not args.target and not args.target_list:
        parser.error("the following arguments are required: -t/--target")
    if args.run_name and ".." in args.run_name:
        parser.error("--run-name must not contain ..")
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
    try:
        results, finding_count = run_jobs(
            jobs_for_mode(args.scan_mode),
            agent=agent,
            binary=binary,
            targets_info=targets_info,
            original_cwd=original_cwd,
            parent=parent,
            instruction=args.instruction or "",
            max_workers=args.max_workers,
            timeout=args.timeout,
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
            "jobs": [
                {"id": result.job_id, "exit": result.exit_code, "timed_out": result.timed_out}
                for result in results
            ],
            "finding_count": finding_count,
        },
    )
    return audit_exit_code(results, finding_count)

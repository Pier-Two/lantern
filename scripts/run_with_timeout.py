#!/usr/bin/env python3
"""
Run a command with a hard timeout and kill its entire process tree if it
overruns. This prevents hung cmake invocations from blocking the build forever.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from typing import List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Execute a command with a timeout. Sends SIGTERM and escalates to "
            "SIGKILL to guarantee teardown of the whole process group."
        )
    )
    parser.add_argument(
        "--timeout",
        required=True,
        type=int,
        help="Seconds to wait before sending SIGTERM to the process group.",
    )
    parser.add_argument(
        "--kill-after",
        type=int,
        default=15,
        help="Seconds to wait after SIGTERM before forcing SIGKILL.",
    )
    parser.add_argument(
        "--label",
        default="command",
        help="Human friendly name used in log messages.",
    )
    parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to execute (must follow a -- separator).",
    )
    args = parser.parse_args()
    # argparse keeps the literal '--' inside REMAINDER; drop it if present.
    if args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    if not args.cmd:
        parser.error("Missing command to execute; supply it after '--'.")
    return args


def kill_process_group(proc: subprocess.Popen) -> None:
    """Send SIGTERM/SIGKILL to the process group pointed to by proc."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def main() -> int:
    args = parse_args()

    if os.name != "posix":
        raise SystemExit("This timeout helper only supports POSIX platforms.")

    # Start the command in its own process group so we can nuke everything.
    proc = subprocess.Popen(  # noqa: S603 (command comes from build script)
        args.cmd,
        preexec_fn=os.setsid,  # type: ignore[arg-type]
    )

    try:
        return proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        sys.stderr.write(
            f"{args.label} exceeded {args.timeout}s; sending SIGTERM to the "
            f"process group.\n"
        )
        kill_process_group(proc)
        try:
            return proc.wait(timeout=args.kill_after)
        except subprocess.TimeoutExpired:
            sys.stderr.write(
                f"{args.label} did not exit after SIGTERM; sending SIGKILL.\n"
            )
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return 124


if __name__ == "__main__":
    raise SystemExit(main())

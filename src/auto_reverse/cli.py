"""Command line entrypoints. Never dynamically loads target or candidate libraries."""

import argparse
import json
import signal
import sys
import threading
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(prog="arm64-recover")
    parser.add_argument("--state-dir", default=".auto-reverse")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Static ELF intake and A0 report")
    analyze.add_argument("--binary", required=True)
    analyze.add_argument("--policy")
    analyze.add_argument("--output", required=True)
    register = commands.add_parser("register-input", help="Stage an immutable local input")
    register.add_argument("binary")
    policy = commands.add_parser("register-policy")
    policy.add_argument("path", nargs="?")
    commands.add_parser("capabilities")
    status = commands.add_parser("get-job")
    status.add_argument("job_id")
    worker = commands.add_parser("worker", help="Process durable static-intake jobs")
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--poll-seconds", type=float, default=1)
    mcp = commands.add_parser("mcp")
    mcp.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    mcp.add_argument("--port", type=int, default=8765)
    verify = commands.add_parser("verify", help="Compare supported machine instructions statically")
    verify.add_argument("--original", required=True)
    verify.add_argument("--candidate", required=True)
    verify.add_argument("--function", help="ELF symbol (otherwise inputs are raw machine bytes)")
    verify.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        if args.command == "mcp":
            from .mcp_server import create_server
            create_server(args.state_dir, port=args.port).run(transport=args.transport)
            return 0
        if args.command == "verify":
            from .intake import extract_function, function_info
            from .semantics import verify_machine_code
            locations = {}
            if args.function:
                original = extract_function(args.original, args.function)
                candidate = extract_function(args.candidate, args.function)
                locations = {
                    "original_address": int(function_info(args.original, args.function)["address"], 16),
                    "candidate_address": int(function_info(args.candidate, args.function)["address"], 16),
                }
            else:
                original = Path(args.original).read_bytes()
                candidate = Path(args.candidate).read_bytes()
            result = verify_machine_code(original, candidate, **locations)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        else:
            from .service import RecoveryService
            service = RecoveryService(args.state_dir)
            if args.command == "analyze":
                result = service.analyze(args.binary, args.output, args.policy)
            elif args.command == "register-input":
                result = service.register_input(args.binary)
            elif args.command == "register-policy":
                result = service.register_policy(args.path)
            elif args.command == "capabilities":
                result = service.describe_capabilities()
            elif args.command == "get-job":
                result = service.domain.get_job(args.job_id)
            elif args.command == "worker":
                if args.poll_seconds <= 0:
                    raise ValueError("poll interval must be positive")
                stop = threading.Event()
                signal.signal(signal.SIGTERM, lambda *_: stop.set())
                signal.signal(signal.SIGINT, lambda *_: stop.set())
                while not stop.is_set():
                    page = service.domain.list_jobs(states=["QUEUED", "RUNNING"], limit=100)
                    for job in page["items"]:
                        if stop.is_set():
                            break
                        try:
                            service.analyze_job(job["job_id"])
                        except Exception as exc:
                            print(f"job {job['job_id']}: {exc}", file=sys.stderr)
                    if args.once:
                        return 0
                    stop.wait(args.poll_seconds)
                return 0
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(f"arm64-recover: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Command line entrypoints. Never dynamically loads target or candidate libraries."""

import argparse
import json
import math
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
    commands.add_parser("domain-rpc", help="Private host stdio RPC; not a model-facing tool")
    ghidra = commands.add_parser("import-ghidra", help="Static headless import and Raw P-code export")
    ghidra.add_argument("--binary", required=True)
    ghidra.add_argument("--output", required=True)
    ghidra.add_argument("--ghidra-home", required=True)
    ghidra.add_argument("--timeout-seconds", type=int, default=300)
    build = commands.add_parser("build-candidate", help="Compile-only controlled Android NDK gate")
    build.add_argument("--source", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--ndk-root", required=True)
    build.add_argument("--api-level", type=int, default=21)
    build.add_argument("--expected-export", action="append")
    recover = commands.add_parser("recover-leaf", help="Recover supported integer leaves, build and verify statically")
    recover.add_argument("--binary", required=True)
    recover.add_argument("--output", required=True)
    recover.add_argument("--ndk-root", required=True)
    recover.add_argument("--api-level", type=int, default=21)
    recover.add_argument("--ghidra-home")
    abi = commands.add_parser("compare-abi", help="Compare original and candidate ELF ABI structure")
    abi.add_argument("--original", required=True)
    abi.add_argument("--candidate", required=True)
    abi.add_argument("--required-export", action="append")
    abi.add_argument("--output")
    scalar = commands.add_parser("inspect-scalar-abi", help="Read bounded original DWARF unsigned declarations")
    scalar.add_argument("--binary", required=True)
    scalar.add_argument("--function", required=True)
    consume = commands.add_parser("consume-evidence", help="Trusted host: classify an actual evidence Proposal")
    consume.add_argument("--execution-key", required=True)
    consume.add_argument("--artifact-ref", required=True)
    freeze = commands.add_parser("freeze-scalar-abi", help="Trusted host: validate and freeze original scalar constraints")
    freeze.add_argument("--execution-key", required=True)
    freeze.add_argument("--artifact-ref", required=True)
    freeze.add_argument("--expected-revision", type=int, required=True)
    current_contracts = commands.add_parser("get-abi-contracts", help="Read current original declaration constraints")
    current_contracts.add_argument("job_id")
    for command_name, command_help in (
        ("list-abi-contracts", "Read frozen declaration constraint history"),
        ("list-evidence-deliveries", "Read auxiliary evidence/gap delivery history"),
    ):
        reader = commands.add_parser(command_name, help=command_help)
        reader.add_argument("job_id")
        reader.add_argument("--cursor", type=int, default=0)
        reader.add_argument("--limit", type=int, default=100)
    queue = commands.add_parser("queue-validation", help="Trusted host: persist independent candidate validation")
    queue.add_argument("--execution-key", required=True)
    queue.add_argument("--candidate-ref", required=True)
    queue.add_argument("--function", required=True)
    queue.add_argument("--idempotency-key", required=True)
    validator = commands.add_parser("validation-worker", help="Compile and statically verify persisted candidates")
    validator.add_argument("--once", action="store_true")
    validator.add_argument("--poll-seconds", type=float, default=1)
    for host_command in (queue, validator):
        host_command.add_argument("--ndk-root", required=True)
        host_command.add_argument("--api-level", type=int, default=21)
        host_command.add_argument("--runtime", choices=["c++_shared", "c++_static"], default="c++_shared")
        host_command.add_argument("--optimization", choices=["O0", "O2"], default="O2")
        host_command.add_argument("--soname", default="librecovered.so")
        host_command.add_argument("--timeout-seconds", type=float, default=30)
    validations = commands.add_parser("list-validations", help="Read independent candidate activities")
    validations.add_argument("job_id")
    validations.add_argument("--cursor", type=int, default=0)
    validations.add_argument("--limit", type=int, default=100)
    validation = commands.add_parser("get-validation", help="Read a persisted validation activity")
    validation.add_argument("job_id")
    validation.add_argument("activity_id")
    postprocess = commands.add_parser("postprocess-candidates", help="Trusted host: classify results and freeze feedback tasks")
    postprocess.add_argument("job_id")
    postprocess.add_argument("--max-activities", type=int, default=64)
    selection = commands.add_parser("get-selection", help="Read current best available candidates and gaps")
    selection.add_argument("job_id")
    feedback = commands.add_parser("list-feedback", help="Read persisted repair/evidence decisions")
    feedback.add_argument("job_id")
    feedback.add_argument("--cursor", type=int, default=0)
    feedback.add_argument("--limit", type=int, default=100)
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
        if args.command == "domain-rpc":
            from .backend_rpc import run_stdio
            run_stdio(args.state_dir)
            return 0
        if args.command == "import-ghidra":
            from .ghidra import analyze_with_ghidra
            result = analyze_with_ghidra(args.binary, args.output, args.ghidra_home,
                                         timeout_seconds=args.timeout_seconds)
        elif args.command == "build-candidate":
            from .build_gate import BuildConfig, build_candidate
            config = BuildConfig(ndk_root=Path(args.ndk_root), api_level=args.api_level,
                                 expected_exports=tuple(args.expected_export) if args.expected_export else None)
            result = build_candidate(Path(args.source).read_text(encoding="utf-8"), Path(args.output), config)
        elif args.command == "recover-leaf":
            from .recovery import recover_subset
            result = recover_subset(args.binary, args.output, args.ndk_root,
                                    api_level=args.api_level, ghidra_home=args.ghidra_home)
        elif args.command == "compare-abi":
            from .abi import compare_elf_abi
            result = compare_elf_abi(args.original, args.candidate,
                                     required_exports=tuple(args.required_export) if args.required_export else None)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        elif args.command == "inspect-scalar-abi":
            from .scalar_abi import extract_scalar_abi
            result = extract_scalar_abi(Path(args.binary).read_bytes(), symbol=args.function)
        elif args.command == "consume-evidence":
            from .evidence_delivery import EvidenceDeliveryService
            result = EvidenceDeliveryService(args.state_dir).consume(args.execution_key, args.artifact_ref)
        elif args.command == "freeze-scalar-abi":
            from .abi_contracts import AbiContractService
            result = AbiContractService(args.state_dir).freeze_from_proposal(
                args.execution_key, args.artifact_ref, expected_revision=args.expected_revision)
        elif args.command == "postprocess-candidates":
            from .postprocessing import CandidatePostprocessor
            result = CandidatePostprocessor(args.state_dir).run(args.job_id, max_activities=args.max_activities)
        elif args.command in {"queue-validation", "validation-worker"}:
            from .build_gate import BuildConfig
            from .candidate_validation import CandidateValidationService
            config = BuildConfig(ndk_root=Path(args.ndk_root), api_level=args.api_level,
                                 runtime=args.runtime, optimization=args.optimization,
                                 soname=args.soname, timeout_seconds=args.timeout_seconds)
            validation_service = CandidateValidationService(args.state_dir, config)
            if args.command == "queue-validation":
                result = validation_service.enqueue(args.execution_key, args.candidate_ref,
                                                     symbol=args.function, idempotency_key=args.idempotency_key)
            elif args.once:
                result = validation_service.run_next()
            else:
                if not math.isfinite(args.poll_seconds) or args.poll_seconds <= 0:
                    raise ValueError("poll interval must be finite and positive")
                stop = threading.Event()
                signal.signal(signal.SIGTERM, lambda *_: stop.set())
                signal.signal(signal.SIGINT, lambda *_: stop.set())
                while not stop.is_set():
                    activity = validation_service.run_next()
                    if activity is not None:
                        print(json.dumps(activity, ensure_ascii=False), flush=True)
                    else:
                        stop.wait(args.poll_seconds)
                return 0
        elif args.command == "mcp":
            from .mcp_server import create_server
            create_server(args.state_dir, port=args.port).run(transport=args.transport)
            return 0
        elif args.command == "verify":
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
                result = service.get_job(args.job_id)
            elif args.command == "get-selection":
                result = service.get_candidate_selection(args.job_id)
            elif args.command == "list-feedback":
                result = service.list_feedback(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-abi-contracts":
                result = service.get_abi_contracts(args.job_id)
            elif args.command == "list-abi-contracts":
                result = service.list_abi_contracts(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "list-evidence-deliveries":
                result = service.list_evidence_deliveries(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "list-validations":
                result = service.list_validations(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-validation":
                result = service.get_validation(args.job_id, args.activity_id)
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

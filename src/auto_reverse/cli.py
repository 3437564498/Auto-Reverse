"""Command line entrypoints. Never dynamically loads target or candidate libraries."""

import argparse
import json
import math
import signal
import sys
import threading
from pathlib import Path


def _host_memory_document(path: str) -> dict:
    """Preserve strict JSON boundaries before constructing host authority."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"non-finite JSON constant: {value}")

    with Path(path).open("rb") as stream:
        encoded = stream.read(65536 + 1)
    if len(encoded) > 65536:
        raise ValueError("host memory document exceeds the bounded 64 KiB profile")
    try:
        document = json.loads(encoded, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError("host memory document exceeds the JSON nesting limit") from exc
    if not isinstance(document, dict):
        raise ValueError("host memory document must be a JSON object")
    return document


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
    project = commands.add_parser("recover-project", help="Trusted static pipeline: recover a supported subset and publish explicit gaps; zero model calls")
    project.add_argument("--binary", required=True)
    project.add_argument("--output", required=True)
    project.add_argument("--ndk-root", required=True)
    project.add_argument("--api-level", "--api", type=int, default=21, dest="api_level")
    project.add_argument("--ghidra-home")
    inventory = commands.add_parser("inspect-library-inventory", help="Observe original exports, function scopes, graph and coverage statically")
    inventory.add_argument("--binary", required=True)
    profile = commands.add_parser("inspect-android-profile", help="Observe Android relocations and lifecycle metadata without executing them")
    profile.add_argument("--binary", required=True)
    profile.add_argument("--api-level", type=int)
    abi = commands.add_parser("compare-abi", help="Compare original and candidate ELF ABI structure")
    abi.add_argument("--original", required=True)
    abi.add_argument("--candidate", required=True)
    abi.add_argument("--required-export", action="append")
    abi.add_argument("--output")
    scalar = commands.add_parser("inspect-scalar-abi", help="Read bounded original DWARF unsigned declarations")
    scalar.add_argument("--binary", required=True)
    scalar.add_argument("--function", required=True)
    layouts = commands.add_parser("inspect-dwarf-layouts", help="Read bounded original DWARF structure layout evidence; calling ABI remains unknown")
    layouts.add_argument("--binary", required=True)
    layouts.add_argument("--max-types", type=int, default=128)
    candidate_layouts = commands.add_parser("inspect-candidate-layouts", help="Compare candidate ordinary structures with original DWARF using fixed Clang; A0 declarations only")
    candidate_layouts.add_argument("--original", required=True)
    candidate_layouts.add_argument("--source", required=True)
    candidate_layouts.add_argument("--type", action="append", required=True, dest="type_names")
    candidate_layouts.add_argument("--ndk-root", required=True)
    candidate_layouts.add_argument("--api-level", type=int, default=21)
    candidate_layouts.add_argument("--timeout-seconds", type=float, default=30)
    candidate_layouts.add_argument("--output", required=True)
    layout_catalog = commands.add_parser("inspect-layout-catalog", help="Read bounded original physical DWARF type identities; A0 only")
    layout_catalog.add_argument("--binary", required=True)
    consume = commands.add_parser("consume-evidence", help="Trusted host: classify an actual evidence Proposal")
    consume.add_argument("--execution-key", required=True)
    consume.add_argument("--artifact-ref", required=True)
    freeze = commands.add_parser("freeze-scalar-abi", help="Trusted host: validate and freeze original scalar constraints")
    freeze.add_argument("--execution-key", required=True)
    freeze.add_argument("--artifact-ref", required=True)
    freeze.add_argument("--expected-revision", type=int, required=True)
    bundle = commands.add_parser("freeze-scalar-abi-bundle", help="Trusted host: atomically freeze a bounded original scalar declaration bundle")
    bundle.add_argument("--execution-key", required=True)
    bundle.add_argument("--artifact-ref", required=True)
    bundle.add_argument("--expected-revision", type=int, required=True)
    layout_bundle = commands.add_parser("freeze-layout-bundle", help="Trusted host: atomically freeze original structure storage declarations")
    layout_bundle.add_argument("--execution-key", required=True)
    layout_bundle.add_argument("--artifact-ref", required=True)
    layout_bundle.add_argument("--expected-revision", type=int, required=True)
    current_contracts = commands.add_parser("get-abi-contracts", help="Read current original declaration constraints")
    current_contracts.add_argument("job_id")
    current_layouts = commands.add_parser("get-layout-contracts", help="Read current original structure declarations without freezing or starting tools")
    current_layouts.add_argument("job_id")
    memory_source = commands.add_parser("register-memory-context-source", help="Trusted host: register an explicit A0 memory assumption source")
    memory_source.add_argument("--job", required=True, dest="job_id")
    memory_source.add_argument("--source", required=True)
    memory_source.add_argument("--idempotency-key", required=True)
    memory_freeze = commands.add_parser("freeze-memory-context", help="Trusted host: freeze an A0 memory assumption; proof consumption remains disabled")
    memory_freeze.add_argument("--job", required=True, dest="job_id")
    memory_freeze.add_argument("--request", required=True)
    memory_freeze.add_argument("--expected-revision", type=int, required=True)
    memory_freeze.add_argument("--idempotency-key", required=True)
    memory_revoke = commands.add_parser("revoke-memory-context", help="Trusted host: revoke a frozen A0 memory assumption")
    memory_revoke.add_argument("--job", required=True, dest="job_id")
    memory_revoke.add_argument("--symbol", required=True)
    memory_revoke.add_argument("--expected-revision", type=int, required=True)
    memory_revoke.add_argument("--idempotency-key", required=True)
    current_memory = commands.add_parser("get-memory-contexts", help="Read current A0 memory assumptions without changing authority or starting tools")
    current_memory.add_argument("job_id")
    for command_name, command_help in (
        ("list-abi-contracts", "Read frozen declaration constraint history"),
        ("list-layout-contracts", "Read original structure constraint history"),
        ("list-memory-context-history", "Read bounded A0 memory assumption history"),
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
    analysis_queue = commands.add_parser("queue-analysis", help="Trusted host: persist a pinned static Ghidra analysis")
    analysis_queue.add_argument("job_id")
    analysis_queue.add_argument("--idempotency-key", required=True)
    analysis_worker = commands.add_parser("analysis-worker", help="Trusted host: export static Raw P-code with durable process ownership")
    analysis_worker.add_argument("--once", action="store_true")
    analysis_worker.add_argument("--poll-seconds", type=float, default=1)
    analysis_worker.add_argument("--worker-id", default="trusted-ghidra-host")
    analysis_worker.add_argument("--activity-id", help="Run only this queued activity")
    for host_command in (analysis_queue, analysis_worker):
        host_command.add_argument("--ghidra-home")
        host_command.add_argument("--java-home")
        host_command.add_argument("--timeout-seconds", type=int, default=300)
    integration_queue = commands.add_parser("queue-integration", help="Trusted host: freeze selected sources for project integration")
    integration_queue.add_argument("job_id")
    integration_queue.add_argument("--idempotency-key", required=True)
    integration_worker = commands.add_parser("integration-worker", help="Trusted host: compile source subsets and verify final linked bytes statically")
    integration_worker.add_argument("--once", action="store_true")
    integration_worker.add_argument("--poll-seconds", type=float, default=1)
    integration_worker.add_argument("--worker-id", default="trusted-project-host")
    for host_command in (queue, validator, integration_queue, integration_worker):
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
    analysis = commands.add_parser("get-analysis", help="Read persisted static analysis evidence and cleanup")
    analysis.add_argument("job_id")
    analysis.add_argument("activity_id")
    analyses = commands.add_parser("list-analyses", help="Read static analysis history")
    analyses.add_argument("job_id")
    analyses.add_argument("--cursor", type=int, default=0)
    analyses.add_argument("--limit", type=int, default=100)
    analysis_report = commands.add_parser("read-analysis-report", help="Read a bounded Job-owned static analysis report")
    analysis_report.add_argument("job_id")
    analysis_report.add_argument("activity_id")
    analysis_report.add_argument("--offset", type=int, default=0)
    analysis_report.add_argument("--limit", type=int, default=65536)
    integration = commands.add_parser("get-integration", help="Read a persisted project integration")
    integration.add_argument("job_id")
    integration.add_argument("activity_id")
    integrations = commands.add_parser("list-integrations", help="Read project integration history")
    integrations.add_argument("job_id")
    integrations.add_argument("--cursor", type=int, default=0)
    integrations.add_argument("--limit", type=int, default=100)
    integration_report = commands.add_parser("read-integration-report", help="Read a bounded Job-owned integration report")
    integration_report.add_argument("job_id")
    integration_report.add_argument("activity_id")
    integration_report.add_argument("--offset", type=int, default=0)
    integration_report.add_argument("--limit", type=int, default=65536)
    publish = commands.add_parser("publish-final-report", help="Trusted host: publish a version-bound static delivery report")
    publish.add_argument("job_id")
    publish.add_argument("--expected-revision", type=int, required=True)
    publish.add_argument("--idempotency-key", required=True)
    publish.add_argument("--integration-activity-id")
    final = commands.add_parser("get-final-delivery", help="Read current static delivery, cleanup and unresolved gaps")
    final.add_argument("job_id")
    finals = commands.add_parser("list-final-deliveries", help="Read historical static deliveries")
    finals.add_argument("job_id")
    finals.add_argument("--cursor", type=int, default=0)
    finals.add_argument("--limit", type=int, default=100)
    final_report = commands.add_parser("read-final-report", help="Read a bounded Job-owned historical delivery")
    final_report.add_argument("job_id")
    final_report.add_argument("delivery_id")
    final_report.add_argument("--offset", type=int, default=0)
    final_report.add_argument("--limit", type=int, default=65536)
    inspect_host = commands.add_parser("inspect-host", help="Trusted host: inspect durable tool ownership without process observation")
    inspect_host.add_argument("--job-id")
    reconcile = commands.add_parser("reconcile-host", help="Trusted host: fence an interrupted tool owner; preserves capacity")
    reconcile.add_argument("--reason", default="trusted host observed an interrupted owner")
    cleanup = commands.add_parser("confirm-host-cleanup", help="Trusted host: observe registered process groups before releasing capacity")
    for host_command in (reconcile, cleanup):
        host_command.add_argument("activity_kind", choices=["validation", "integration", "analysis"])
        host_command.add_argument("activity_id")
        host_command.add_argument("--expected-run-number", type=int, required=True)
        host_command.add_argument("--expected-owner-hash", required=True)
        host_command.add_argument("--expected-worker-id", required=True)
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
        elif args.command == "recover-project":
            from .static_pipeline import recover_project
            result = recover_project(args.binary, args.output, args.ndk_root,
                                     api_level=args.api_level, ghidra_home=args.ghidra_home)
        elif args.command == "inspect-library-inventory":
            from .library_inventory import inspect_library_inventory
            result = inspect_library_inventory(Path(args.binary).read_bytes())
        elif args.command == "inspect-android-profile":
            from .android_profile import inspect_android_profile
            result = inspect_android_profile(Path(args.binary).read_bytes(), api_level=args.api_level)
        elif args.command == "compare-abi":
            from .abi import compare_elf_abi
            result = compare_elf_abi(args.original, args.candidate,
                                     required_exports=tuple(args.required_export) if args.required_export else None)
            if args.output:
                Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        elif args.command == "inspect-scalar-abi":
            from .scalar_abi import extract_scalar_abi
            result = extract_scalar_abi(Path(args.binary).read_bytes(), symbol=args.function)
        elif args.command == "inspect-dwarf-layouts":
            from .dwarf_layout import inspect_dwarf_layouts
            with Path(args.binary).open("rb") as stream:
                binary = stream.read(64 * 1024 * 1024 + 1)
            if len(binary) > 64 * 1024 * 1024:
                raise ValueError("DWARF layout input exceeds the bounded 64 MiB profile")
            result = inspect_dwarf_layouts(binary, max_types=args.max_types)
        elif args.command == "inspect-candidate-layouts":
            from .build_gate import BuildConfig
            from .candidate_layout import inspect_candidate_layouts
            with Path(args.original).open("rb") as stream:
                binary = stream.read(64 * 1024 * 1024 + 1)
            if len(binary) > 64 * 1024 * 1024:
                raise ValueError("candidate layout original exceeds the bounded 64 MiB profile")
            with Path(args.source).open("rb") as stream:
                source = stream.read(1024 * 1024 + 1)
            if len(source) > 1024 * 1024:
                raise ValueError("candidate layout source exceeds the bounded 1 MiB profile")
            config = BuildConfig(ndk_root=Path(args.ndk_root), api_level=args.api_level,
                                 timeout_seconds=args.timeout_seconds)
            result = inspect_candidate_layouts(source.decode("utf-8"), binary, tuple(args.type_names),
                                               config, Path(args.output))
        elif args.command == "inspect-layout-catalog":
            from .layout_contracts import inspect_original_layout_catalog
            with Path(args.binary).open("rb") as stream:
                binary = stream.read(64 * 1024 * 1024 + 1)
            if len(binary) > 64 * 1024 * 1024:
                raise ValueError("layout catalog input exceeds the bounded 64 MiB profile")
            result = inspect_original_layout_catalog(binary)
        elif args.command == "consume-evidence":
            from .evidence_delivery import EvidenceDeliveryService
            result = EvidenceDeliveryService(args.state_dir).consume(args.execution_key, args.artifact_ref)
        elif args.command == "freeze-scalar-abi":
            from .abi_contracts import AbiContractService
            result = AbiContractService(args.state_dir).freeze_from_proposal(
                args.execution_key, args.artifact_ref, expected_revision=args.expected_revision)
        elif args.command == "freeze-scalar-abi-bundle":
            from .type_solver import TypeSolverService
            result = TypeSolverService(args.state_dir).freeze_bundle_from_proposal(
                args.execution_key, args.artifact_ref, expected_revision=args.expected_revision)
        elif args.command == "freeze-layout-bundle":
            from .layout_contracts import LayoutContractService
            result = LayoutContractService(args.state_dir).freeze_bundle_from_proposal(
                args.execution_key, args.artifact_ref, expected_revision=args.expected_revision)
        elif args.command == "register-memory-context-source":
            from .memory_contexts import HostMemorySourceDocument, MemoryContextService
            document = HostMemorySourceDocument.model_validate(_host_memory_document(args.source))
            result = MemoryContextService(args.state_dir).register_source(
                args.job_id, document.model_dump(mode="json"), idempotency_key=args.idempotency_key)
        elif args.command == "freeze-memory-context":
            from .memory_contexts import HostMemoryContextRequest, MemoryContextService
            request = HostMemoryContextRequest.model_validate(_host_memory_document(args.request))
            result = MemoryContextService(args.state_dir).freeze(
                args.job_id, request.model_dump(mode="json"), expected_revision=args.expected_revision,
                idempotency_key=args.idempotency_key)
        elif args.command == "revoke-memory-context":
            from .memory_contexts import MemoryContextService
            result = MemoryContextService(args.state_dir).revoke(
                args.job_id, args.symbol, expected_revision=args.expected_revision,
                idempotency_key=args.idempotency_key)
        elif args.command == "publish-final-report":
            from .final_report import FinalReportService
            result = FinalReportService(args.state_dir).publish(
                args.job_id, expected_revision=args.expected_revision, idempotency_key=args.idempotency_key,
                integration_activity_id=args.integration_activity_id)
        elif args.command == "inspect-host":
            from .host_reconcile import HostReconciliationService
            result = HostReconciliationService(args.state_dir).inspect(args.job_id)
        elif args.command in {"reconcile-host", "confirm-host-cleanup"}:
            from .host_reconcile import HostReconciliationService
            reconciliation = HostReconciliationService(args.state_dir)
            operation = reconciliation.reconcile_stale if args.command == "reconcile-host" else reconciliation.confirm_cleanup
            guard = {"expected_run_number": args.expected_run_number,
                     "expected_owner_hash": args.expected_owner_hash,
                     "expected_worker_id": args.expected_worker_id}
            if args.command == "reconcile-host":
                guard["reason"] = args.reason
            result = operation(args.activity_kind, args.activity_id, **guard)
        elif args.command == "postprocess-candidates":
            from .postprocessing import CandidatePostprocessor
            result = CandidatePostprocessor(args.state_dir).run(args.job_id, max_activities=args.max_activities)
        elif args.command in {"queue-analysis", "analysis-worker"}:
            from .analysis_service import GhidraAnalysisService
            analysis_service = GhidraAnalysisService(
                args.state_dir, args.ghidra_home, args.java_home, timeout_seconds=args.timeout_seconds)
            if args.command == "queue-analysis":
                result = analysis_service.enqueue(args.job_id, idempotency_key=args.idempotency_key)
            elif args.once:
                result = analysis_service.run_next(args.worker_id, activity_id=args.activity_id)
            else:
                if not math.isfinite(args.poll_seconds) or args.poll_seconds <= 0:
                    raise ValueError("poll interval must be finite and positive")
                stop = threading.Event()
                signal.signal(signal.SIGTERM, lambda *_: stop.set())
                signal.signal(signal.SIGINT, lambda *_: stop.set())
                while not stop.is_set():
                    activity = analysis_service.run_next(args.worker_id, activity_id=args.activity_id)
                    if activity is not None:
                        print(json.dumps(activity, ensure_ascii=False), flush=True)
                    else:
                        stop.wait(args.poll_seconds)
                return 0
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
        elif args.command in {"queue-integration", "integration-worker"}:
            from .build_gate import BuildConfig
            from .project_service import ProjectIntegrationService
            config = BuildConfig(ndk_root=Path(args.ndk_root), api_level=args.api_level,
                                 runtime=args.runtime, optimization=args.optimization,
                                 soname=args.soname, timeout_seconds=args.timeout_seconds)
            integration_service = ProjectIntegrationService(args.state_dir, config)
            if args.command == "queue-integration":
                result = integration_service.enqueue(args.job_id, idempotency_key=args.idempotency_key)
            elif args.once:
                result = integration_service.run_next(args.worker_id)
            else:
                if not math.isfinite(args.poll_seconds) or args.poll_seconds <= 0:
                    raise ValueError("poll interval must be finite and positive")
                stop = threading.Event()
                signal.signal(signal.SIGTERM, lambda *_: stop.set())
                signal.signal(signal.SIGINT, lambda *_: stop.set())
                while not stop.is_set():
                    activity = integration_service.run_next(args.worker_id)
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
            elif args.command == "get-layout-contracts":
                result = service.get_layout_contracts(args.job_id)
            elif args.command == "list-layout-contracts":
                result = service.list_layout_contracts(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-memory-contexts":
                result = service.get_memory_contexts(args.job_id)
            elif args.command == "list-memory-context-history":
                result = service.list_memory_context_history(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "list-evidence-deliveries":
                result = service.list_evidence_deliveries(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "list-validations":
                result = service.list_validations(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-validation":
                result = service.get_validation(args.job_id, args.activity_id)
            elif args.command == "list-analyses":
                result = service.list_analyses(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-analysis":
                result = service.get_analysis(args.job_id, args.activity_id)
            elif args.command == "read-analysis-report":
                result = service.read_analysis_report(args.job_id, args.activity_id, args.offset, args.limit)
            elif args.command == "list-integrations":
                result = service.list_integrations(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "get-integration":
                result = service.get_integration(args.job_id, args.activity_id)
            elif args.command == "read-integration-report":
                result = service.read_integration_report(args.job_id, args.activity_id, args.offset, args.limit)
            elif args.command == "get-final-delivery":
                result = service.get_final_delivery(args.job_id)
            elif args.command == "list-final-deliveries":
                result = service.list_final_deliveries(args.job_id, cursor=args.cursor, limit=args.limit)
            elif args.command == "read-final-report":
                result = service.read_final_report(args.job_id, args.delivery_id, args.offset, args.limit)
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

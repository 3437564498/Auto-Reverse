import type { Agent } from '@deepseek-ai/dsh-agent';
import type { SubagentCapabilities, SubagentResult } from '@deepseek-ai/dsh-subagent';
import type { ObjectJsonSchema } from '@deepseek-ai/dsh-tools';

export const DSH_COMMIT = 'd743267388641bc76f17c45ce8b4c231aed1d32c';
export const ROLES = ['planning', 'evidence', 'type_abi', 'recovery', 'reviewer', 'repair', 'integration', 'naming', 'reporting'] as const;
export type Role = typeof ROLES[number];
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface WorkPackage {
  schema_version: 1;
  job_id: string;
  task_id: string;
  attempt_id: string;
  role: Role;
  /** Absent/empty type_ids preserves the historical canonical WorkPackage. */
  scope: { function_ids: string[]; region_ids: string[]; type_ids?: string[] };
  input_snapshot_id: string;
  contract_revision: number;
  evidence_manifest_ref: string;
  candidate_namespace: string;
  dependencies: string[];
  allowed_operations: string[];
  limits: { wall_timeout_seconds: number; max_tool_calls: number; max_agent_depth: 1 };
  stop_conditions: string[];
  missing_evidence_policy: 'report_gap';
}

/** Frozen task contract before the Domain atomically creates an Attempt. */
export type WorkPackageSpec = Omit<WorkPackage, 'attempt_id'>;

export interface AttemptBinding {
  work: WorkPackage;
  epoch: number;
  execution_key: string;
  /** Frozen host-selected instructions, never a parent conversation. */
  instructions?: string;
}

export interface Proposal {
  schema_version: 1;
  job_id: string;
  task_id: string;
  attempt_id: string;
  input_snapshot_id: string;
  contract_revision: number;
  disposition: 'PROPOSED';
  artifact_refs: string[];
  evidence_refs: string[];
  assumptions: string[];
  gaps: string[];
  requested_followup_tasks: { [key: string]: Json }[];
}

export interface WorkerLease {
  /** Host secret: must never be present in prompts, proposal or logs. */
  token: string;
}

export interface ActivationIdentity { session_id: string; activation_id: string }
export interface ProposalReceipt { execution_key: string; disposition: 'RECORDED'; event_sequence: number }
export interface BatchPlan { batch_ref: string; job_id: string; tasks: WorkPackageSpec[] }
export interface AcquiredWorker { binding: AttemptBinding; lease: WorkerLease }
export interface ProfileReport {
  dsh_commit: string;
  provider: string;
  /** Host attestation of its effective, inspected configuration. */
  inspected: boolean;
  missingPreflight?: string[];
  max_active_subagents: number;
  max_tokens_as_success: boolean;
  global_worker_limit: 32;
  control_channel_authenticated: boolean;
  tool_mode: 'native' | 'ptc' | 'unobserved';
}

/** Cross-runtime quota, queue, fencing and persistence belong to the Domain service. */
export interface DomainClient {
  loadBatch(batchRef: string): Promise<BatchPlan>;
  inspectProfile(): Promise<ProfileReport>;
  /** Null means durably queued in Domain; the runner does not busy retry. */
  tryAcquireWorker(task: WorkPackageSpec, signal: AbortSignal): Promise<AcquiredWorker | null>;
  bindActivation(binding: AttemptBinding, lease: WorkerLease, identity: ActivationIdentity): Promise<void>;
  commitProposal(binding: AttemptBinding, lease: WorkerLease, proposal: Proposal): Promise<ProposalReceipt>;
  recordFailure(binding: AttemptBinding, code: string): Promise<void>;
  /** Invalidates submission leases before child disposal. Must be idempotent. */
  cancelJob(jobId: string): Promise<void>;
  /** Confirms every owned tool resource stopped; dispose alone is insufficient. */
  confirmToolCleanup(binding: AttemptBinding, lease: WorkerLease): Promise<boolean>;
  releaseWorker(binding: AttemptBinding, lease: WorkerLease): Promise<void>;
  quarantineWorker(binding: AttemptBinding, lease: WorkerLease, reason: string): Promise<void>;
  readEvidence(binding: AttemptBinding, ref: string, cursor: string | undefined, signal: AbortSignal): Promise<Json>;
  stageCandidate(binding: AttemptBinding, name: string, content: string, signal: AbortSignal): Promise<Json>;
  readContract(binding: AttemptBinding, signal: AbortSignal): Promise<Json>;
  reportTask(binding: AttemptBinding, reason: 'NEEDS_EVIDENCE' | 'BLOCKED' | 'NO_PROGRESS', details: string, signal: AbortSignal): Promise<Json>;
  auditTool(binding: AttemptBinding | undefined, info: { session_id: string; name: string; is_error: boolean; job_id?: string; batch_ref?: string }): Promise<void>;
}

/** Separate trusted host control, never a model tool or SDK request() extension. */
export interface RecoveryHost {
  authorizeRoot(sessionId: string): Promise<{ job_id: string; batch_ref: string } | undefined>;
  /** Installs authenticated control transport; disposer drains owned resources. */
  installControl(handler: (jobId: string) => Promise<void>): () => void | Promise<void>;
}

export interface ActivationHandle extends ActivationIdentity {
  result: Promise<SubagentResult>;
  dispose(): Promise<void>;
}
export interface ActivationRequest {
  binding: AttemptBinding;
  parent: Agent;
  signal: AbortSignal;
  outputSchema: ObjectJsonSchema;
  persona: string;
  maxDepth: 1;
  /** Empty inherited allowlist: worker tools are registered in its own scope. */
  toolFilter: { allow: readonly string[] };
  delivery: 'caller';
}
/** Injectable for lifecycle tests. Real implementation wraps the official seam. */
export interface ActivationProvider {
  readonly name: string;
  capabilities(): SubagentCapabilities & { fresh: boolean; local: boolean };
  startActivation(request: ActivationRequest): Promise<ActivationHandle>;
}

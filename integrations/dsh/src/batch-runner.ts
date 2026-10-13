import type { Agent } from '@deepseek-ai/dsh-agent';
import { DSH_COMMIT, ROLES, type ActivationHandle, type ActivationProvider, type AttemptBinding, type DomainClient, type WorkerLease } from './contracts.js';
import { PROPOSAL_SCHEMA, validateProposal, validateWork } from './proposal.js';

export interface WorkerOutcome { attempt_id: string; state: 'RECORDED' | 'QUEUED' | 'FAILED' | 'CANCELLED' | 'QUARANTINED'; code?: string }
export interface BatchOutcome { job_id: string; batch_ref: string; workers: WorkerOutcome[] }
interface WorkerEntry { binding: AttemptBinding; lease?: WorkerLease; handle?: ActivationHandle; startup?: Promise<ActivationHandle>; disposal?: Promise<void>; quarantined: boolean; released: boolean }
interface ActiveBatch { job_id: string; batch_ref: string; controller: AbortController; stopRequested: boolean; entries: WorkerEntry[]; cancellation?: Promise<void>; settled: Promise<void>; settle: () => void }

async function deadline<T>(operation: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('CLEANUP_TIMEOUT')), ms); })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

async function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  let abort!: () => void;
  const interrupted = new Promise<never>((_, reject) => { abort = () => reject(new Error('ABORTED')); });
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  try { return await Promise.race([operation, interrupted]); }
  finally { signal.removeEventListener('abort', abort); }
}

export class BatchRunner {
  private active: ActiveBatch | undefined;
  private quarantinedRuntime = false;
  constructor(private readonly domain: DomainClient, private readonly provider: ActivationProvider, private readonly cleanupTimeoutMs = 10_000) {}
  current(): { job_id: string; batch_ref: string; cancelling: boolean } | undefined {
    const active = this.active;
    return active === undefined ? undefined : { job_id: active.job_id, batch_ref: active.batch_ref, cancelling: active.stopRequested };
  }
  /** Synchronously reserves this Runtime, including plan/profile/startup awaits. */
  runBatch(batchRef: string, jobId: string, parent: Agent): Promise<BatchOutcome> {
    if (this.quarantinedRuntime) return Promise.reject(new Error('RUNTIME_QUARANTINED'));
    if (this.active !== undefined) return Promise.reject(new Error('RUNTIME_BATCH_BUSY'));
    let settle!: () => void;
    const active: ActiveBatch = { job_id: jobId, batch_ref: batchRef, controller: new AbortController(), stopRequested: false, entries: [], settled: new Promise<void>(resolve => { settle = resolve; }), settle: () => settle() };
    this.active = active;
    return this.execute(active, parent).finally(() => {
      active.settle();
      if (this.active === active) this.active = undefined;
    });
  }
  private async preflight(): Promise<void> {
    const caps = this.provider.capabilities();
    if (!caps.fresh || !caps.local || !caps.agentOptions || !caps.outputSchema || !caps.depthLimit || !caps.toolFilter || !caps.persona) throw new Error('UNSUPPORTED_DSH_BACKEND');
    const report = await this.domain.inspectProfile();
    if (!report.inspected || report.dsh_commit !== DSH_COMMIT || report.provider !== this.provider.name || report.max_active_subagents !== 32 || report.max_tokens_as_success !== false || report.global_worker_limit !== 32 || !report.control_channel_authenticated || report.tool_mode !== 'native') throw new Error('UNSAFE_DSH_PROFILE');
  }
  private async execute(active: ActiveBatch, parent: Agent): Promise<BatchOutcome> {
    const plan = structuredClone(await abortable(this.domain.loadBatch(active.batch_ref), active.controller.signal));
    if (plan.job_id !== active.job_id || plan.batch_ref !== active.batch_ref) throw new Error('BATCH_AUTHORIZATION_MISMATCH');
    // A batch can contain a bounded ready list larger than 32: excess remains durably queued.
    if (plan.attempts.length > 64) throw new Error('BATCH_TOO_LARGE');
    const identities = new Set<string>();
    for (const binding of plan.attempts) {
      validateWork(binding);
      if (binding.work.job_id !== active.job_id || binding.work.schema_version !== 1 || !ROLES.includes(binding.work.role) || identities.has(binding.work.attempt_id) || !binding.work.attempt_id || !binding.work.task_id || !binding.execution_key || !Number.isSafeInteger(binding.epoch) || binding.epoch < 0 || binding.work.limits.max_agent_depth !== 1 || !Number.isSafeInteger(binding.work.limits.max_tool_calls) || binding.work.limits.max_tool_calls <= 0 || !Number.isFinite(binding.work.limits.wall_timeout_seconds) || binding.work.limits.wall_timeout_seconds <= 0) throw new Error('INVALID_FROZEN_BATCH');
      identities.add(binding.work.attempt_id);
    }
    await abortable(this.preflight(), active.controller.signal);
    const outcomes: WorkerOutcome[] = [];
    // Domain grants shared capacity atomically. No local counter pretends to enforce all Runtimes.
    const workers = plan.attempts.map(binding => {
      const entry: WorkerEntry = { binding, quarantined: false, released: false };
      active.entries.push(entry);
      return this.executeWorker(active, entry, parent).then(outcome => { outcomes.push(outcome); });
    });
    const settled = await Promise.allSettled(workers);
    const failed = settled.find(result => result.status === 'rejected');
    if (failed?.status === 'rejected') throw failed.reason;
    return { job_id: active.job_id, batch_ref: active.batch_ref, workers: outcomes };
  }
  private async executeWorker(active: ActiveBatch, entry: WorkerEntry, parent: Agent): Promise<WorkerOutcome> {
    const binding = entry.binding;
    let outcome: WorkerOutcome = { attempt_id: binding.work.attempt_id, state: 'FAILED' };
    const controller = new AbortController();
    const abort = () => controller.abort();
    active.controller.signal.addEventListener('abort', abort, { once: true });
    if (active.controller.signal.aborted) controller.abort();
    const timer = setTimeout(() => controller.abort(), binding.work.limits.wall_timeout_seconds * 1000);
    const disposeOnAbort = () => { if (entry.handle !== undefined) void this.dispose(entry).catch(() => undefined); };
    controller.signal.addEventListener('abort', disposeOnAbort, { once: true });
    try {
      if (controller.signal.aborted || active.stopRequested) return { attempt_id: binding.work.attempt_id, state: 'CANCELLED' };
      const lease = await this.domain.tryAcquireWorker(binding, controller.signal);
      if (lease === null) return { attempt_id: binding.work.attempt_id, state: 'QUEUED' };
      entry.lease = lease;
      if (controller.signal.aborted || active.stopRequested) throw new Error('CANCELLED_BEFORE_START');
      entry.startup = this.provider.startActivation({ binding, parent, signal: controller.signal, outputSchema: structuredClone(PROPOSAL_SCHEMA), persona: `You are the ${binding.work.role} worker for exactly one frozen work package. Investigate evidence and submit a proposal. Never execute binaries, claim independent quality acceptance, delegate work, or change the runtime.`, maxDepth: 1, toolFilter: { allow: [] }, delivery: 'caller' });
      // Retain late publication even after a bounded wait has quarantined the lease.
      void entry.startup.then(handle => {
        entry.handle = handle;
        if (entry.quarantined || controller.signal.aborted) void this.dispose(entry).catch(() => undefined);
      }, () => undefined);
      entry.handle = await abortable(entry.startup, controller.signal);
      // Covers abort after publication but before the start promise fulfilled.
      if (controller.signal.aborted) { await this.dispose(entry); throw new Error('CANCELLED_AFTER_START'); }
      await this.domain.bindActivation(binding, lease, { session_id: entry.handle.session_id, activation_id: entry.handle.activation_id });
      if (controller.signal.aborted) throw new Error('CANCELLED_AFTER_BIND');
      const result = await abortable(entry.handle.result, controller.signal);
      if (controller.signal.aborted || active.stopRequested) throw new Error(active.stopRequested ? 'CANCELLED' : 'WALL_TIMEOUT');
      // Transport "ok" and finalResponse are never proposal evidence.
      if (result.stopReason !== 'completed') throw new Error(result.stopReason === 'max-tokens' ? 'OUTPUT_TRUNCATED' : 'ACTIVATION_NOT_COMPLETED');
      const proposal = validateProposal(result.structured, binding);
      if (active.stopRequested) throw new Error('CANCELLED_BEFORE_COMMIT');
      await this.domain.commitProposal(binding, lease, proposal);
      outcome = { attempt_id: binding.work.attempt_id, state: 'RECORDED' };
    } catch (error) {
      // Never persist provider diagnostics or arbitrary Error messages that may contain secrets.
      const known = ['OUTPUT_TRUNCATED', 'ACTIVATION_NOT_COMPLETED', 'INVALID_PROPOSAL_SCHEMA', 'PROPOSAL_IDENTITY_MISMATCH', 'ARTIFACT_SCOPE_MISMATCH', 'INVALID_CONTRACT_REVISION', 'WALL_TIMEOUT'];
      const code = active.stopRequested ? 'CANCELLED' : controller.signal.aborted ? 'WALL_TIMEOUT' : error instanceof Error && known.includes(error.message) ? error.message : 'ADAPTER_INFRASTRUCTURE_FAILURE';
      outcome = { attempt_id: binding.work.attempt_id, state: active.stopRequested ? 'CANCELLED' : 'FAILED', code };
      await this.domain.recordFailure(binding, code);
    } finally {
      clearTimeout(timer);
      active.controller.signal.removeEventListener('abort', abort);
      controller.signal.removeEventListener('abort', disposeOnAbort);
      if (entry.lease !== undefined && !entry.released && !entry.quarantined) {
        try {
          if (entry.startup !== undefined) await deadline(entry.startup.then(() => undefined, () => undefined), this.cleanupTimeoutMs);
          await this.dispose(entry);
          const confirmed = await deadline(this.domain.confirmToolCleanup(binding, entry.lease), this.cleanupTimeoutMs);
          if (!confirmed) throw new Error('TOOL_CLEANUP_UNCONFIRMED');
          await this.domain.releaseWorker(binding, entry.lease);
          entry.released = true;
        } catch {
          await this.quarantine(entry);
          outcome = { attempt_id: binding.work.attempt_id, state: 'QUARANTINED', code: 'CLEANUP_UNCONFIRMED' };
        }
      }
    }
    return outcome;
  }
  private dispose(entry: WorkerEntry): Promise<void> {
    if (entry.handle === undefined) return Promise.resolve();
    entry.disposal ??= deadline(Promise.resolve().then(() => entry.handle!.dispose()), this.cleanupTimeoutMs);
    return entry.disposal;
  }
  private async quarantine(entry: WorkerEntry): Promise<void> {
    if (entry.quarantined || entry.released || entry.lease === undefined) return;
    entry.quarantined = true;
    this.quarantinedRuntime = true;
    await this.domain.quarantineWorker(entry.binding, entry.lease, 'CLEANUP_UNCONFIRMED');
  }
  /** Authentication is owned by the host's separate control endpoint. */
  cancel(jobId: string): Promise<void> {
    const active = this.active;
    if (active === undefined || active.job_id !== jobId) return this.domain.cancelJob(jobId);
    if (active.cancellation !== undefined) return active.cancellation;
    active.stopRequested = true;
    active.cancellation = (async () => {
      await this.domain.cancelJob(jobId);
      // Durable fencing precedes real disposal; stopRequested blocked local commits immediately.
      active.controller.abort();
      // Pending starts see the AbortSignal; published starts receive exact disposal.
      await Promise.allSettled(active.entries.filter(entry => entry.handle !== undefined).map(entry => this.dispose(entry)));
      try { await deadline(active.settled, this.cleanupTimeoutMs); }
      catch { await Promise.all(active.entries.map(entry => this.quarantine(entry))); }
    })();
    return active.cancellation;
  }
}

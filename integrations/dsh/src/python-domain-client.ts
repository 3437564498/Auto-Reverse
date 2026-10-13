import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import type { AcquiredWorker, ActivationIdentity, AttemptBinding, BatchPlan, DomainClient, Json, ProfileReport, Proposal, ProposalReceipt, WorkerLease, WorkPackageSpec } from './contracts.js';

export interface PythonDomainOptions {
  /** Executable only, never shell syntax or arbitrary command arguments. */
  python: string;
  repository: string;
  stateDir: string;
  inspectProfile: () => Promise<ProfileReport>;
  rpcTimeoutMs?: number;
  workerId?: string;
}
export class DomainRpcError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'DomainRpcError'; }
}
interface Pending { resolve: (value: unknown) => void; reject: (error: Error) => void; clear: () => void }

/** Fixed-command private JSON-lines child. Never forwards stderr or serializes diagnostics. */
class RpcProcess {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly pending = new Map<string, Pending>();
  private readonly exited: Promise<void>;
  private stopping = false;
  private failed = false;
  private count = 0;
  constructor(options: PythonDomainOptions, private readonly onFatal: (code: string) => Promise<void>) {
    this.child = spawn(options.python, ['-m', 'auto_reverse.cli', '--state-dir', resolve(options.stateDir), 'domain-rpc'], {
      cwd: resolve(options.repository), shell: false, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PYTHONUNBUFFERED: '1', PYTHONDONTWRITEBYTECODE: '1' },
    });
    // Stderr is drained privately. Python exception text can contain leases or input data.
    this.child.stderr.resume();
    this.exited = new Promise(resolveExit => this.child.once('close', () => resolveExit()));
    this.child.on('error', () => { void this.fatal('RPC_PROCESS_ERROR'); });
    this.child.on('close', () => { if (!this.stopping) void this.fatal('RPC_PROCESS_CLOSED'); });
    this.child.stdin.on('error', () => { if (!this.stopping) void this.fatal('RPC_PIPE_ERROR'); });
    let fragmentBytes = 0;
    this.child.stdout.on('data', (chunk: Buffer) => {
      const last = chunk.lastIndexOf(10);
      fragmentBytes = last < 0 ? fragmentBytes + chunk.length : chunk.length - last - 1;
      if (fragmentBytes > 4 * 1024 * 1024) void this.fatal('RPC_FRAME_TOO_LARGE');
    });
    const lines = createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    lines.on('line', line => {
      if (this.failed || this.stopping) return;
      if (Buffer.byteLength(line) > 4 * 1024 * 1024) { void this.fatal('RPC_FRAME_TOO_LARGE'); return; }
      let value: unknown;
      try { value = JSON.parse(line); } catch { void this.fatal('RPC_INVALID_FRAME'); return; }
      const reply = value as { id?: unknown; result?: unknown; error?: { code?: unknown } };
      if (reply === null || typeof reply !== 'object' || typeof reply.id !== 'string' || !this.pending.has(reply.id) || Object.hasOwn(reply, 'result') === Object.hasOwn(reply, 'error')) { void this.fatal('RPC_INVALID_FRAME'); return; }
      const pending = this.pending.get(reply.id)!;
      this.pending.delete(reply.id); pending.clear();
      if (reply.error !== undefined) pending.reject(new DomainRpcError(typeof reply.error.code === 'string' && /^[a-zA-Z0-9_.-]{1,100}$/.test(reply.error.code) ? reply.error.code : 'RPC_DOMAIN_ERROR'));
      else pending.resolve(reply.result);
    });
  }
  request(method: string, params: object, timeoutMs: number, signal?: AbortSignal): Promise<unknown> {
    if (this.failed || this.stopping) return Promise.reject(new DomainRpcError('RPC_UNAVAILABLE'));
    if (signal?.aborted) return Promise.reject(new DomainRpcError('RPC_ABORTED_BEFORE_SEND'));
    return new Promise((resolveRequest, reject) => {
      const id = String(++this.count);
      const interrupt = () => { void this.fatal('RPC_ABORTED'); };
      const timer = setTimeout(() => { void this.fatal('RPC_TIMEOUT'); }, timeoutMs);
      const clear = () => { clearTimeout(timer); signal?.removeEventListener('abort', interrupt); };
      this.pending.set(id, { resolve: resolveRequest, reject, clear });
      signal?.addEventListener('abort', interrupt, { once: true });
      this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n', error => { if (error !== null && error !== undefined) void this.fatal('RPC_WRITE_FAILED'); });
    });
  }
  private async fatal(code: string): Promise<void> {
    if (this.failed || this.stopping) return;
    this.failed = true;
    // Fence before returning a timed-out read to the tool runtime. Unknown late lease
    // grants are covered by worker.fence, not by assuming the RPC never ran.
    await this.onFatal(code).catch(() => undefined);
    for (const entry of this.pending.values()) { entry.clear(); entry.reject(new DomainRpcError(code)); }
    this.pending.clear();
  }
  async close(rejectPending = true): Promise<void> {
    if (!this.stopping) {
      this.stopping = true;
      if (rejectPending) {
        for (const entry of this.pending.values()) { entry.clear(); entry.reject(new DomainRpcError('RPC_CLOSED')); }
        this.pending.clear();
      }
      this.child.stdin.end();
      this.child.kill('SIGTERM');
    }
    if (await boundedExit(this.exited, 1000)) return;
    this.child.kill('SIGKILL');
    if (!await boundedExit(this.exited, 3000)) throw new DomainRpcError('RPC_EXIT_UNCONFIRMED');
  }
}
async function boundedExit(exit: Promise<void>, timeout: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([exit.then(() => true), new Promise<boolean>(resolveTimer => { timer = setTimeout(() => resolveTimer(false), timeout); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}

/** Real Python SQLite/CAS bridge; the provider/model is a separate concern. */
export class PythonDomainClient implements DomainClient {
  readonly workerId: string;
  private channel: RpcProcess;
  private readonly ownedWorkerIds = new Set<string>();
  private readonly activationIdentities = new Map<string, ActivationIdentity>();
  private readonly bindingReady = new Map<string, { promise: Promise<boolean>; finish: (ready: boolean) => void }>();
  private readonly bindings = new Map<string, AttemptBinding>();
  private readonly auditCredentials = new Map<string, WorkerLease>();
  private readonly leases = new Map<string, WorkerLease>();
  private readonly pendingTools = new Map<string, number>();
  private fenced = false;
  private closed = false;
  private fenceTask: Promise<void> | undefined;
  private readonly timeout: number;
  constructor(private readonly options: PythonDomainOptions) {
    this.workerId = options.workerId ?? `dsh-host-${randomUUID()}`;
    this.timeout = options.rpcTimeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.timeout) || this.timeout < 1) throw new Error('INVALID_RPC_TIMEOUT');
    this.channel = this.makeChannel();
  }
  private makeChannel(): RpcProcess { return new RpcProcess(this.options, code => this.fence(code)); }
  private fence(_code: string): Promise<void> {
    this.fenced = true;
    for (const binding of this.bindingReady.values()) binding.finish(false);
    this.fenceTask ??= (async () => {
      const old = this.channel;
      await old.close(false);
      if (this.closed) return;
      // A new private RPC process performs the durable worker fence. It cannot
      // inherit a blocked read or a partially consumed JSON frame.
      const recovery = new RpcProcess(this.options, async () => { await recovery.close(); });
      this.channel = recovery;
      for (const workerId of this.ownedWorkerIds) await recovery.request('worker.fence', { worker_id: workerId }, this.timeout);
    })();
    return this.fenceTask;
  }
  private async rpc<T>(method: string, params: object, signal?: AbortSignal): Promise<T> {
    if (this.closed) throw new DomainRpcError('RPC_CLOSED');
    if (this.fenceTask !== undefined) await this.fenceTask;
    return await this.channel.request(method, params, this.timeout, signal) as T;
  }
  private lease(binding: AttemptBinding): WorkerLease {
    if (this.fenced) throw new DomainRpcError('WORKER_FENCED');
    const lease = this.leases.get(binding.work.attempt_id);
    if (lease === undefined) throw new DomainRpcError('HOST_LEASE_MISSING');
    return lease;
  }
  private async tool(binding: AttemptBinding, method: string, params: object, signal: AbortSignal): Promise<Json> {
    const id = binding.work.attempt_id;
    const lease = this.lease(binding);
    const ready = this.bindingReady.get(id);
    if (ready === undefined) throw new DomainRpcError('HOST_LEASE_MISSING');
    this.pendingTools.set(id, (this.pendingTools.get(id) ?? 0) + 1);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort!: () => void;
    try {
      const interrupted = new Promise<never>((_, reject) => { abort = () => reject(new DomainRpcError('BINDING_WAIT_ABORTED')); timer = setTimeout(() => reject(new DomainRpcError('BINDING_WAIT_TIMEOUT')), this.timeout); });
      signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
      if (!await Promise.race([ready.promise, interrupted])) throw new DomainRpcError('ACTIVATION_BINDING_FAILED');
      // Recheck after publication: a concurrent read cancellation may have fenced this host.
      this.checkedLease(binding, lease);
      if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
      signal.removeEventListener('abort', abort);
      return await this.rpc<Json>(method, { ...params, attempt_id: id, lease_token: lease.token }, signal);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      this.pendingTools.set(id, (this.pendingTools.get(id) ?? 1) - 1);
    }
  }
  createBatch(jobId: string, taskIds: string[], idempotencyKey: string): Promise<{ batch_ref: string }> { return this.rpc('batch.create', { job_id: jobId, task_ids: taskIds, idempotency_key: idempotencyKey }); }
  loadBatch(batchRef: string): Promise<BatchPlan> { return this.rpc('batch.load', { batch_ref: batchRef }); }
  async inspectProfile(): Promise<ProfileReport> {
    const report = await this.options.inspectProfile();
    const actual = await this.rpc<{ global_worker_limit: number; protocol_version: number; static_only: boolean }>('domain.inspect', {});
    if (actual.global_worker_limit !== 32 || actual.protocol_version !== 1 || actual.static_only !== true) { report.inspected = false; report.missingPreflight = [...(report.missingPreflight ?? []), 'domain.quota_static_protocol']; }
    return { ...report, global_worker_limit: actual.global_worker_limit as 32 };
  }
  async tryAcquireWorker(task: WorkPackageSpec, signal: AbortSignal): Promise<AcquiredWorker | null> {
    if (this.fenced) throw new DomainRpcError('WORKER_FENCED');
    const workerId = `${this.workerId}:${randomUUID()}`;
    this.ownedWorkerIds.add(workerId);
    const acquired = await this.rpc<AcquiredWorker | null>('task.lease', { task_id: task.task_id, worker_id: workerId, ttl_seconds: task.limits.wall_timeout_seconds + 60 }, signal);
    if (acquired !== null) {
      let finish!: (ready: boolean) => void; const promise = new Promise<boolean>(yes => { finish = yes; });
      this.bindingReady.set(acquired.binding.work.attempt_id, { promise, finish });
      this.leases.set(acquired.binding.work.attempt_id, acquired.lease); this.auditCredentials.set(acquired.binding.work.attempt_id, acquired.lease); this.bindings.set(acquired.binding.work.attempt_id, acquired.binding); }
    return acquired;
  }
  async bindActivation(binding: AttemptBinding, lease: WorkerLease, identity: ActivationIdentity): Promise<void> {
    try {
      await this.rpc('attempt.bind', { attempt_id: binding.work.attempt_id, lease_token: this.checkedLease(binding, lease).token, ...identity });
      this.activationIdentities.set(binding.work.attempt_id, identity);
      this.bindingReady.get(binding.work.attempt_id)?.finish(true);
    } catch (error) { this.bindingReady.get(binding.work.attempt_id)?.finish(false); throw error; }
  }
  async commitProposal(binding: AttemptBinding, lease: WorkerLease, proposal: Proposal): Promise<ProposalReceipt> {
    return this.rpc('proposal.commit', { proposal, lease_token: this.checkedLease(binding, lease).token, execution_key: binding.execution_key });
  }
  async recordFailure(binding: AttemptBinding, code: string): Promise<void> { await this.rpc('attempt.failure', { attempt_id: binding.work.attempt_id, code }); }
  async cancelJob(jobId: string): Promise<void> { await this.rpc('job.cancel', { job_id: jobId }); }
  async confirmToolCleanup(binding: AttemptBinding, lease: WorkerLease): Promise<boolean> {
    return !this.fenced && this.leases.get(binding.work.attempt_id)?.token === lease.token && (this.pendingTools.get(binding.work.attempt_id) ?? 0) === 0;
  }
  async releaseWorker(binding: AttemptBinding, lease: WorkerLease): Promise<void> {
    if (!await this.confirmToolCleanup(binding, lease)) throw new DomainRpcError('TOOL_CLEANUP_UNCONFIRMED');
    await this.rpc('attempt.cleanup', { attempt_id: binding.work.attempt_id, confirmed: true });
    this.leases.delete(binding.work.attempt_id);
  }
  async quarantineWorker(binding: AttemptBinding, _lease: WorkerLease, _reason: string): Promise<void> { await this.rpc('attempt.cleanup', { attempt_id: binding.work.attempt_id, confirmed: false }); }
  async readEvidence(binding: AttemptBinding, ref: string, cursor: string | undefined, signal: AbortSignal): Promise<Json> {
    const offset = cursor === undefined ? 0 : Number(cursor);
    if (!Number.isSafeInteger(offset) || offset < 0 || (cursor !== undefined && !/^(0|[1-9][0-9]*)$/.test(cursor))) throw new DomainRpcError('INVALID_EVIDENCE_CURSOR');
    const page = await this.tool(binding, 'evidence.read', { ref, offset, limit: 64 * 1024 }, signal) as { [key: string]: Json };
    const next = page.next_cursor;
    if (next !== null && typeof next === 'object' && !Array.isArray(next) && typeof next.offset === 'number') page.next_cursor = String(next.offset);
    return page;
  }
  async stageCandidate(binding: AttemptBinding, name: string, content: string, signal: AbortSignal): Promise<Json> {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(name) || name.includes('..')) throw new DomainRpcError('INVALID_CANDIDATE_NAME');
    if (Buffer.byteLength(content) > 1024 * 1024) throw new DomainRpcError('CANDIDATE_TOO_LARGE');
    let json: unknown;
    try { json = JSON.parse(content); } catch { throw new DomainRpcError('INVALID_CANDIDATE_JSON'); }
    if (json === null || typeof json !== 'object' || Array.isArray(json)) throw new DomainRpcError('INVALID_CANDIDATE_JSON');
    return this.tool(binding, 'artifact.stage', { name, content }, signal);
  }
  readContract(binding: AttemptBinding, signal: AbortSignal): Promise<Json> { return this.tool(binding, 'contract.read', {}, signal); }
  reportTask(binding: AttemptBinding, reason: 'NEEDS_EVIDENCE' | 'BLOCKED' | 'NO_PROGRESS', details: string, signal: AbortSignal): Promise<Json> { return this.tool(binding, 'task.report', { reason, details }, signal); }
  async auditTool(binding: AttemptBinding | undefined, info: { session_id: string; name: string; is_error: boolean; job_id?: string; batch_ref?: string }): Promise<void> {
    const lease = binding === undefined ? undefined : this.auditCredentials.get(binding.work.attempt_id);
    await this.rpc('audit.write', { ...info, ...(binding === undefined ? {} : { attempt_id: binding.work.attempt_id, lease_token: lease?.token }) });
  }
  receipt(executionKey: string): Promise<ProposalReceipt | null> { return this.rpc('receipt.get', { execution_key: executionKey }); }
  async receiptSummaries(jobId: string, taskIds: string[]): Promise<Json[]> {
    const summaries: Json[] = [];
    for (const binding of this.bindings.values()) {
      if (binding.work.job_id !== jobId || !taskIds.includes(binding.work.task_id)) continue;
      const receipt = await this.receipt(binding.execution_key);
      summaries.push({ job_id: jobId, task_id: binding.work.task_id, attempt_id: binding.work.attempt_id, ...(this.activationIdentities.get(binding.work.attempt_id) ?? {}), receipt: receipt === null ? null : { disposition: receipt.disposition, event_sequence: receipt.event_sequence } });
    }
    return summaries;
  }
  private checkedLease(binding: AttemptBinding, lease: WorkerLease): WorkerLease {
    if (this.lease(binding).token !== lease.token) throw new DomainRpcError('HOST_LEASE_MISMATCH');
    return lease;
  }
  /** Shutdown fences all owned attempts; it does not claim model/tool disposal. */
  async close(): Promise<void> {
    if (this.closed) return;
    for (const binding of this.bindingReady.values()) binding.finish(false);
    try { if (!this.fenced) for (const workerId of this.ownedWorkerIds) await this.rpc('worker.fence', { worker_id: workerId }); }
    finally { this.closed = true; this.auditCredentials.clear(); this.leases.clear(); await this.channel.close(); }
  }
}

import assert from 'node:assert/strict';
import { setImmediate as tick } from 'node:timers/promises';
import { test } from 'node:test';
import { Context, FiberState } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { SessionId } from '@deepseek-ai/dsh-session';
import type { SubagentResult } from '@deepseek-ai/dsh-subagent';
import { BatchRunner } from '../src/batch-runner.js';
import { DSH_COMMIT, type ActivationHandle, type ActivationProvider, type ActivationRequest, type AttemptBinding, type BatchPlan, type DomainClient, type Json, type ProfileReport, type Proposal, type ProposalReceipt, type WorkerLease } from '../src/contracts.js';
import { StaticPolicy } from '../src/policy.js';
import { frozenPrompt, PROPOSAL_SCHEMA, SHARED_PROPOSAL_SCHEMA, validateProposal, validateWork } from '../src/proposal.js';
import * as plugin from '../src/plugin.js';

function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: Error) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const parent = { id: SessionId('root') } as Agent;
function binding(index = 0): AttemptBinding {
  return {
    epoch: 1, execution_key: `secret-execution-${index}`,
    work: { schema_version: 1, job_id: 'job-1', task_id: `task-${index}`, attempt_id: `attempt-${index}`, role: 'recovery',
      scope: { function_ids: [`fn-${index}`], region_ids: [] }, input_snapshot_id: 'snapshot-1', contract_revision: 1,
      evidence_manifest_ref: `evidence://job-1/fn-${index}`, candidate_namespace: `candidate://job-1/attempt-${index}`,
      dependencies: [], allowed_operations: ['evidence_read', 'contract_read', 'candidate_submit', 'task_report'],
      limits: { wall_timeout_seconds: 30, max_tool_calls: 80, max_agent_depth: 1 },
      stop_conditions: ['proposal_submitted'], missing_evidence_policy: 'report_gap',
    },
  };
}
function proposal(b: AttemptBinding): Proposal {
  const w = b.work;
  return { schema_version: 1, job_id: w.job_id, task_id: w.task_id, attempt_id: w.attempt_id, input_snapshot_id: w.input_snapshot_id, contract_revision: w.contract_revision, disposition: 'PROPOSED', artifact_refs: [`${w.candidate_namespace}/source`], evidence_refs: [w.evidence_manifest_ref], assumptions: [], gaps: [], requested_followup_tasks: [] };
}
class Domain implements DomainClient {
  readonly events: string[] = []; leases = 0; peak = 0; cancelled = false;
  readonly commits: Proposal[] = []; readonly releases: string[] = []; readonly quarantines: string[] = [];
  readonly failures: string[] = []; readonly bound: string[] = []; toolCleanup = true;
  profile: ProfileReport = { dsh_commit: DSH_COMMIT, provider: 'spawn', inspected: true, max_active_subagents: 32, max_tokens_as_success: false, global_worker_limit: 32, control_channel_authenticated: true, tool_mode: 'native' };
  constructor(readonly plan: BatchPlan) {}
  async loadBatch(): Promise<BatchPlan> { return this.plan; }
  async inspectProfile(): Promise<ProfileReport> { return this.profile; }
  async tryAcquireWorker(b: AttemptBinding): Promise<WorkerLease | null> {
    if (this.cancelled || this.leases === 32) { this.events.push(`queued:${b.work.attempt_id}`); return null; }
    this.leases += 1; this.peak = Math.max(this.peak, this.leases); return { token: `secret-lease-${b.work.attempt_id}` };
  }
  async bindActivation(_b: AttemptBinding, _l: WorkerLease, id: { session_id: string; activation_id: string }): Promise<void> { this.bound.push(id.activation_id); }
  async commitProposal(b: AttemptBinding, _l: WorkerLease, p: Proposal): Promise<ProposalReceipt> {
    if (this.cancelled) throw new Error('FENCED'); this.commits.push(p); return { execution_key: b.execution_key, disposition: 'RECORDED', event_sequence: this.commits.length };
  }
  async recordFailure(_b: AttemptBinding, code: string): Promise<void> { this.failures.push(code); }
  async cancelJob(): Promise<void> { this.cancelled = true; this.events.push('fenced'); }
  async confirmToolCleanup(): Promise<boolean> { return this.toolCleanup; }
  async releaseWorker(b: AttemptBinding): Promise<void> { this.events.push('released'); this.releases.push(b.work.attempt_id); this.leases -= 1; }
  async quarantineWorker(b: AttemptBinding): Promise<void> { this.quarantines.push(b.work.attempt_id); }
  async readEvidence(): Promise<Json> { return {}; }
  async readContract(): Promise<Json> { return {}; }
  async reportTask(): Promise<Json> { return {}; }
  async auditTool(): Promise<void> {}
}
class Provider implements ActivationProvider {
  readonly name = 'spawn'; readonly starts: ActivationRequest[] = []; readonly disposed: string[] = [];
  caps = { agentOptions: true, outputSchema: true, depthLimit: true, toolFilter: true, persona: true, fresh: true, local: true };
  capabilities() { return this.caps; }
  hook: ((request: ActivationRequest) => Promise<ActivationHandle>) | undefined;
  async startActivation(request: ActivationRequest): Promise<ActivationHandle> {
    this.starts.push(request);
    if (this.hook !== undefined) return this.hook(request);
    return this.handle(request, Promise.resolve({ output: [], stopReason: 'completed', structured: proposal(request.binding) }));
  }
  handle(request: ActivationRequest, result: Promise<SubagentResult>, dispose?: () => Promise<void>): ActivationHandle {
    return { session_id: `fresh-${request.binding.work.attempt_id}`, activation_id: `run-${request.binding.work.attempt_id}`, result,
      dispose: async () => { this.disposed.push(request.binding.work.attempt_id); if (dispose !== undefined) await dispose(); },
    };
  }
}
function fixture(count = 1) { const domain = new Domain({ batch_ref: 'batch-1', job_id: 'job-1', attempts: Array.from({ length: count }, (_, i) => binding(i)) }); const provider = new Provider(); return { domain, provider, runner: new BatchRunner(domain, provider, 20) }; }

// These are injected adapter tests, not claims of real model or Harness execution.
test('two injected fresh worker handles keep distinct provider identities and record proposals independently', async () => {
  const { runner, domain, provider } = fixture(2);
  const outcome = await runner.runBatch('batch-1', 'job-1', parent);
  assert.deepEqual(outcome.workers.map(w => w.state), ['RECORDED', 'RECORDED']);
  assert.equal(new Set(domain.bound).size, 2); assert.equal(domain.commits.length, 2); assert.equal(domain.releases.length, 2);
  for (const request of provider.starts) {
    assert.equal(request.delivery, 'caller'); assert.equal(request.maxDepth, 1); assert.deepEqual(request.toolFilter, { allow: [] });
    assert.equal(request.outputSchema.additionalProperties, false);
    assert.equal(frozenPrompt(request.binding).includes('secret-execution'), false);
    assert.equal(frozenPrompt(request.binding).includes('secret-lease'), false);
  }
});

test('proposal projection matches shared fields and strict final shared schema rejects drift', () => {
  assert.deepEqual(Object.keys(PROPOSAL_SCHEMA.properties!).sort(), Object.keys(SHARED_PROPOSAL_SCHEMA.properties as object).sort());
  const b = binding(); validateWork(b); validateProposal(proposal(b), b);
  const follows = { ...proposal(b), requested_followup_tasks: [{ reason: 'evidence', scope: 'fn-0' }] };
  validateProposal(follows, b);
  assert.throws(() => validateProposal({ ...proposal(b), quality: 'A' }, b), /INVALID_PROPOSAL_SCHEMA/);
  assert.throws(() => validateProposal({ ...proposal(b), artifact_refs: [] }, b), /INVALID_PROPOSAL_SCHEMA/);
  assert.throws(() => validateProposal({ ...proposal(b), requested_followup_tasks: ['free string'] }, b), /INVALID_PROPOSAL_SCHEMA/);
  assert.throws(() => validateProposal({ ...proposal(b), disposition: 'RECORDED' }, b), /INVALID_PROPOSAL_SCHEMA/);
  assert.throws(() => validateProposal({ ...proposal(b), attempt_id: 'other-attempt' }, b), /IDENTITY_MISMATCH/);
  assert.throws(() => validateProposal({ ...proposal(b), artifact_refs: ['candidate://other/source'] }, b), /ARTIFACT_SCOPE_MISMATCH/);
  const missing = { ...proposal(b) } as Partial<Proposal>; delete missing.gaps;
  assert.throws(() => validateProposal(missing, b), /INVALID_PROPOSAL_SCHEMA/);
});

for (const reason of ['max-tokens', 'error', 'aborted'] as const) test(`noncompleted ${reason} is rejected even with a valid-looking structured proposal`, async () => {
  const { domain, provider, runner } = fixture();
  provider.hook = async request => provider.handle(request, Promise.resolve({ output: [], stopReason: reason, structured: proposal(request.binding) }));
  const outcome = await runner.runBatch('batch-1', 'job-1', parent);
  assert.equal(outcome.workers[0]?.state, 'FAILED'); assert.equal(domain.commits.length, 0); assert.equal(domain.releases.length, 1);
  if (reason === 'max-tokens') assert.deepEqual(domain.failures, ['OUTPUT_TRUNCATED']);
});

test('completed but truncated/missing output never commits a receipt', async () => {
  const { domain, provider, runner } = fixture();
  provider.hook = async request => provider.handle(request, Promise.resolve({ output: [{ type: 'text', text: '{"schema_version":1' }], stopReason: 'completed' }));
  await runner.runBatch('batch-1', 'job-1', parent);
  assert.equal(domain.commits.length, 0); assert.deepEqual(domain.failures, ['INVALID_PROPOSAL_SCHEMA']);
});

test('exact Agent binding, root restrictions and own-scope additions deny shell and delegation', () => {
  const policy = new StaticPolicy(); const worker = { id: SessionId('worker') } as Agent;
  policy.bindRoot(parent, 'job-1', 'batch-1'); policy.bindWorker(worker, binding());
  for (const name of ['Bash', 'shell', 'spawn', 'delegate', 'run_code', 'workflow', 'install_plugin', 'dynamic_load']) {
    assert.equal(policy.deny(worker, name), 'STATIC_TOOL_DENIED'); assert.equal(policy.deny(parent, name), 'ROOT_TOOL_DENIED');
  }
  assert.equal(policy.deny({ id: worker.id } as Agent, 'evidence_read'), 'UNBOUND_AGENT');
  assert.equal(policy.deny(worker, 'evidence_read'), undefined); assert.equal(policy.deny(worker, 'structured_output'), undefined);
  assert.throws(() => policy.assertSurface(worker, ['structured_output', 'shell']), /UNSAFE_EFFECTIVE_TOOL_SURFACE/);
  policy.deactivate(worker); assert.equal(policy.deny(worker, 'evidence_read'), 'INACTIVE_ATTEMPT');
});

test('backend preflight rejects unsupported SDK subprocess features and false profile capacity', async () => {
  const f = fixture(); f.provider.caps.outputSchema = false;
  await assert.rejects(f.runner.runBatch('batch-1', 'job-1', parent), /UNSUPPORTED_DSH_BACKEND/); assert.equal(f.provider.starts.length, 0);
  const g = fixture(); g.domain.profile.max_active_subagents = 8;
  await assert.rejects(g.runner.runBatch('batch-1', 'job-1', parent), /UNSAFE_DSH_PROFILE/); assert.equal(g.domain.leases, 0);
  const h = fixture(); h.domain.profile.max_tokens_as_success = true;
  await assert.rejects(h.runner.runBatch('batch-1', 'job-1', parent), /UNSAFE_DSH_PROFILE/);
});

test('one Runtime rejects simultaneous batches and unrelated Jobs while startup is pending', async () => {
  const { runner, provider } = fixture(); const start = deferred<ActivationHandle>();
  provider.hook = () => start.promise;
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  await assert.rejects(runner.runBatch('batch-2', 'job-2', parent), /RUNTIME_BATCH_BUSY/);
  start.resolve(provider.handle(provider.starts[0]!, Promise.resolve({ output: [], stopReason: 'completed', structured: proposal(binding()) })));
  await run;
});

test('32 active plus extra stays queued in the injected authoritative Domain without startup retries', async () => {
  const { runner, domain, provider } = fixture(33); const finish = deferred<SubagentResult>();
  provider.hook = async request => provider.handle(request, finish.promise);
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  assert.equal(domain.peak, 32); assert.equal(provider.starts.length, 32); assert.equal(domain.leases, 32);
  finish.resolve({ output: [], stopReason: 'aborted' });
  const outcome = await run; assert.equal(outcome.workers.filter(w => w.state === 'QUEUED').length, 1); assert.equal(domain.leases, 0);
});

test('cancel during startup waits late publication then exact disposal after durable fencing', async () => {
  const { runner, provider, domain } = fixture(); const startup = deferred<ActivationHandle>(); const finish = deferred<SubagentResult>();
  provider.hook = () => startup.promise;
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  const cancel = runner.cancel('job-1');
  startup.resolve(provider.handle(provider.starts[0]!, finish.promise, async () => { domain.events.push('disposed'); finish.resolve({ output: [], stopReason: 'aborted' }); }));
  await cancel; const outcome = await run;
  assert.equal(outcome.workers[0]?.state, 'CANCELLED'); assert.equal(domain.commits.length, 0); assert.equal(provider.disposed.length, 1);
  assert.ok(domain.events.indexOf('fenced') < domain.events.indexOf('disposed')); assert.equal(domain.releases.length, 1);
});

test('published cancellation disposes exactly once and never commits a raced result', async () => {
  const { runner, provider, domain } = fixture(); const finish = deferred<SubagentResult>();
  provider.hook = async request => provider.handle(request, finish.promise, async () => { assert.equal(domain.cancelled, true); finish.resolve({ output: [], stopReason: 'completed', structured: proposal(request.binding) }); });
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  await Promise.all([runner.cancel('job-1'), runner.cancel('job-1')]); await run;
  assert.equal(provider.disposed.length, 1); assert.equal(domain.commits.length, 0); assert.equal(domain.releases.length, 1);
});

test('cleanup failure quarantines lease and prevents reuse of the Runtime', async () => {
  const { runner, provider, domain } = fixture();
  provider.hook = async request => provider.handle(request, Promise.resolve({ output: [], stopReason: 'completed', structured: proposal(request.binding) }), async () => { throw new Error('private-error'); });
  const outcome = await runner.runBatch('batch-1', 'job-1', parent);
  assert.equal(outcome.workers[0]?.state, 'QUARANTINED'); assert.equal(domain.releases.length, 0); assert.equal(domain.leases, 1); assert.equal(domain.quarantines.length, 1);
  await assert.rejects(runner.runBatch('batch-1', 'job-1', parent), /RUNTIME_QUARANTINED/);
});

test('unconfirmed tool resources cannot return worker capacity even after child disposal', async () => {
  const { runner, domain } = fixture(); domain.toolCleanup = false;
  const outcome = await runner.runBatch('batch-1', 'job-1', parent);
  assert.equal(outcome.workers[0]?.state, 'QUARANTINED'); assert.equal(domain.releases.length, 0); assert.equal(domain.leases, 1);
});

test('provider ignoring abort during startup ends bounded and late handle is disposed without releasing quarantined slot', async () => {
  const { runner, provider, domain } = fixture(); const startup = deferred<ActivationHandle>();
  provider.hook = () => startup.promise;
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  await runner.cancel('job-1'); const outcome = await run;
  assert.equal(domain.quarantines.length, 1); assert.equal(domain.releases.length, 0); assert.equal(domain.leases, 1);
  startup.resolve(provider.handle(provider.starts[0]!, Promise.resolve({ output: [], stopReason: 'aborted' })));
  await tick(); assert.equal(provider.disposed.length, 1); assert.equal(domain.releases.length, 0);
  assert.ok(['QUARANTINED', 'CANCELLED'].includes(outcome.workers[0]!.state));
});

test('published result never settles and dispose fails: cancellation still finishes bounded and quarantined', async () => {
  const { runner, provider, domain } = fixture();
  provider.hook = async request => provider.handle(request, new Promise(() => {}), async () => { throw new Error('cleanup-failed'); });
  const run = runner.runBatch('batch-1', 'job-1', parent); await tick();
  await runner.cancel('job-1'); const outcome = await run;
  assert.equal(outcome.workers[0]?.state, 'QUARANTINED'); assert.equal(domain.releases.length, 0); assert.equal(domain.leases, 1);
});

test('real Cordis entry is dependency-gated rather than pretending missing services worked', async () => {
  const ctx = new Context(); const fiber = ctx.plugin(plugin);
  await tick(); assert.equal(fiber.state, FiberState.PENDING);
  await fiber.dispose();
});

test('wall deadline alone aborts a permanently pending result and preserves failed-disposal occupancy', async () => {
  const { runner, provider, domain } = fixture(); domain.plan.attempts[0]!.work.limits.wall_timeout_seconds = 1;
  provider.hook = async request => provider.handle(request, new Promise(() => {}), () => new Promise(() => {}));
  const started = Date.now();
  const outcome = await runner.runBatch('batch-1', 'job-1', parent);
  assert.ok(Date.now() - started < 3000);
  assert.equal(outcome.workers[0]?.state, 'QUARANTINED');
  assert.deepEqual(domain.failures, ['WALL_TIMEOUT']); assert.equal(domain.releases.length, 0); assert.equal(domain.leases, 1);
});

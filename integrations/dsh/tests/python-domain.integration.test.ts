import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setImmediate as tick, setTimeout as delay } from 'node:timers/promises';
import type { Agent } from '@deepseek-ai/dsh-agent';
import type { SubagentResult } from '@deepseek-ai/dsh-subagent';
import { PythonDomainClient } from '../src/python-domain-client.js';
import { BatchRunner } from '../src/batch-runner.js';
import { DSH_COMMIT, type ActivationHandle, type ActivationProvider, type ActivationRequest, type AttemptBinding, type BatchPlan, type ProfileReport, type Proposal, type WorkPackageSpec } from '../src/contracts.js';
import { validateProposal, frozenPrompt } from '../src/proposal.js';

const repository = fileURLToPath(new URL('../../../../', import.meta.url));
const python = process.env.AUTO_REVERSE_PYTHON ?? join(repository, '.venv/bin/python');
const parent = { id: 'injected-root' } as Agent;
// Explicit provider fixture attestation: integration is genuine SQLite/RPC/CAS,
// but these providers do not claim Cordis/model execution or an effective Profile.
const injectedProfile: ProfileReport = { dsh_commit: DSH_COMMIT, provider: 'spawn', inspected: true, max_active_subagents: 32, max_tokens_as_success: false, global_worker_limit: 32, control_channel_authenticated: true, tool_mode: 'native' };

class SetupRpc {
  readonly child;
  private readonly pending = new Map<string, { yes: (value: any) => void; no: (error: Error) => void }>();
  private next = 0;
  constructor(readonly stateDir: string) {
    this.child = spawn(python, ['-m', 'auto_reverse.cli', '--state-dir', stateDir, 'domain-rpc'], { cwd: repository, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stderr.resume();
    createInterface({ input: this.child.stdout }).on('line', line => {
      const response = JSON.parse(line); const entry = this.pending.get(response.id)!; this.pending.delete(response.id);
      if (response.error) entry.no(new Error(response.error.code)); else entry.yes(response.result);
    });
  }
  call(method: string, params: object): Promise<any> {
    return new Promise((yes, no) => { const id = String(++this.next); this.pending.set(id, { yes, no }); this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n'); });
  }
  async close(): Promise<void> { const closed = new Promise<void>(yes => this.child.once('close', () => yes())); this.child.stdin.end(); await closed; }
}
async function fixture(count: number) {
  const stateDir = await mkdtemp(join(tmpdir(), 'dsh-ledger-')); const setup = new SetupRpc(stateDir);
  const input = await setup.call('input.register', { content: 'infrastructure-only immutable fixture; no target library' });
  const policy = await setup.call('policy.register', {});
  const job = await setup.call('job.submit', { input_ref: input.input_ref, policy_ref: policy.policy_ref, idempotency_key: randomUUID() });
  const data = Buffer.concat([Buffer.from([0xff, 0x00, 0x80]), Buffer.alloc(70_000, 0x5a)]);
  const evidence = await setup.call('evidence.register', { content_base64: data.toString('base64') });
  const foreign = await setup.call('evidence.register', { value: { unauthorized: true } });
  const taskIds: string[] = [];
  for (let index = 0; index < count; index++) {
    const taskId = `task-${index}`; taskIds.push(taskId);
    const manifest = await setup.call('manifest.create', { job_id: job.job_id, task_id: taskId, artifact_refs: [evidence.artifact_ref] });
    const work: WorkPackageSpec = { schema_version: 1, job_id: job.job_id, task_id: taskId, role: 'reviewer', scope: { function_ids: [`fn-${index}`], region_ids: [] },
      input_snapshot_id: job.input_snapshot_id, contract_revision: job.contract_revision, dependencies: [], evidence_manifest_ref: manifest.evidence_manifest_ref, candidate_namespace: `candidate://${job.job_id}/${taskId}`,
      allowed_operations: ['evidence_read', 'contract_read', 'candidate_submit', 'task_report'], limits: { wall_timeout_seconds: 30, max_tool_calls: 80, max_agent_depth: 1 }, stop_conditions: ['proposal_submitted'], missing_evidence_policy: 'report_gap' };
    await setup.call('task.create', { work_package: work });
  }
  const batch = await setup.call('batch.create', { job_id: job.job_id, task_ids: taskIds, idempotency_key: randomUUID() });
  const plan = await setup.call('batch.load', { batch_ref: batch.batch_ref }) as BatchPlan;
  const client = () => new PythonDomainClient({ python, repository, stateDir, inspectProfile: async () => structuredClone(injectedProfile) });
  return { stateDir, setup, plan, data, evidence, foreign, client, dispose: async () => { await setup.close(); await rm(stateDir, { recursive: true, force: true }); } };
}
function proposed(binding: AttemptBinding, artifactRef: string): Proposal {
  const w = binding.work;
  return { schema_version: 1, job_id: w.job_id, task_id: w.task_id, attempt_id: w.attempt_id, input_snapshot_id: w.input_snapshot_id, contract_revision: w.contract_revision, disposition: 'PROPOSED', artifact_refs: [artifactRef], evidence_refs: [w.evidence_manifest_ref], assumptions: [], gaps: ['model acceptance intentionally not run'], requested_followup_tasks: [] };
}
class InjectedProvider implements ActivationProvider {
  readonly name = 'spawn'; readonly starts: ActivationRequest[] = []; readonly disposed: string[] = [];
  readonly identities: { session_id: string; activation_id: string }[] = [];
  hook: ((request: ActivationRequest) => Promise<SubagentResult>) | undefined;
  constructor(readonly domain: PythonDomainClient) {}
  capabilities() { return { fresh: true, local: true, agentOptions: true, outputSchema: true, depthLimit: true, persona: true, toolFilter: true }; }
  async startActivation(request: ActivationRequest): Promise<ActivationHandle> {
    this.starts.push(request);
    const identity = { session_id: `injected-session-${randomUUID()}`, activation_id: `injected-activation-${randomUUID()}` }; this.identities.push(identity);
    const result = (async () => {
      if (this.hook !== undefined) return this.hook(request);
      await this.domain.readContract(request.binding, request.signal);
      await this.domain.readEvidence(request.binding, request.binding.work.evidence_manifest_ref, undefined, request.signal);
      const staged = await this.domain.stageCandidate(request.binding, 'proposal.json', JSON.stringify({ kind: 'infrastructure-fixture', task_id: request.binding.work.task_id }), request.signal) as { artifact_ref: string };
      return { output: [], stopReason: 'completed', structured: proposed(request.binding, staged.artifact_ref) } as SubagentResult;
    })();
    return { ...identity, result, dispose: async () => { this.disposed.push(request.binding.work.attempt_id); } };
  }
}

test('real Python JSON-lines + SQLite/CAS records two distinct injected activations and durable receipts across restart', async () => {
  const f = await fixture(2); const domain = f.client();
  try {
    const provider = new InjectedProvider(domain); const runner = new BatchRunner(domain, provider);
    const outcome = await runner.runBatch(f.plan.batch_ref, f.plan.job_id, parent);
    assert.deepEqual(outcome.workers.map(worker => worker.state), ['RECORDED', 'RECORDED']);
    assert.equal(new Set(provider.identities.map(identity => identity.session_id)).size, 2);
    for (const request of provider.starts) {
      assert.ok(request.binding.work.attempt_id.startsWith('attempt-'));
      assert.equal(frozenPrompt(request.binding).includes('lease_token'), false);
      assert.equal(frozenPrompt(request.binding).includes(request.binding.execution_key), false);
      const receipt = await domain.receipt(request.binding.execution_key); assert.equal(receipt?.disposition, 'RECORDED');
    }
    await domain.auditTool(undefined, { session_id: parent.id, job_id: f.plan.job_id, batch_ref: f.plan.batch_ref, name: 'run_recovery_batch', is_error: false });
    for (let index = 0; index < provider.starts.length; index++) await domain.auditTool(provider.starts[index]!.binding, { session_id: provider.identities[index]!.session_id, name: 'structured_output', is_error: false });
    const before = await f.setup.call('job.get', { job_id: f.plan.job_id });
    assert.equal(before.quality.artifact_level, null); assert.equal(before.quality.semantic.status, 'NOT_CHECKED');
    await domain.close();
    const restarted = f.client();
    try {
      assert.deepEqual(await restarted.loadBatch(f.plan.batch_ref), f.plan);
      for (const request of provider.starts) assert.equal((await restarted.receipt(request.binding.execution_key))?.disposition, 'RECORDED');
    } finally { await restarted.close(); }
  } finally { await domain.close(); await f.dispose(); }
});

test('real bound evidence pages are lossless, scoped and fingerprint checked; fake artifacts and quality upgrades fail', async () => {
  const f = await fixture(2); const domain = f.client(); const signal = new AbortController().signal;
  try {
    const acquired = (await domain.tryAcquireWorker(f.plan.tasks[0]!, signal))!;
    await assert.rejects(f.setup.call('evidence.read', { attempt_id: acquired.binding.work.attempt_id, lease_token: acquired.lease.token, ref: f.evidence.artifact_ref }), /ACTIVATION_NOT_BOUND/);
    const earlyTool = domain.readContract(acquired.binding, signal);
    assert.equal(await domain.confirmToolCleanup(acquired.binding, acquired.lease), false);
    await domain.bindActivation(acquired.binding, acquired.lease, { session_id: 'real-binding-fixture', activation_id: 'activation-fixture' });
    assert.equal((await earlyTool as any).work.attempt_id, acquired.binding.work.attempt_id);
    const first = await domain.readEvidence(acquired.binding, f.evidence.artifact_ref, undefined, signal) as any;
    assert.equal(first.next_cursor, '65536'); assert.equal(first.complete, false);
    const second = await domain.readEvidence(acquired.binding, f.evidence.artifact_ref, first.next_cursor, signal) as any;
    assert.deepEqual(Buffer.concat([Buffer.from(first.data_base64, 'base64'), Buffer.from(second.data_base64, 'base64')]), f.data);
    assert.equal(first.sha256, createHash('sha256').update(f.data).digest('hex'));
    await assert.rejects(domain.readEvidence(acquired.binding, f.foreign.artifact_ref, undefined, signal), /EVIDENCE_DENIED/);
    await assert.rejects(domain.stageCandidate(acquired.binding, '../escape', '{}', signal), /INVALID_CANDIDATE_NAME/);
    await assert.rejects(domain.stageCandidate(acquired.binding, 'text', 'not-json', signal), /INVALID_CANDIDATE_JSON/);
    const staged = await domain.stageCandidate(acquired.binding, 'candidate.json', '{"proposal":true}', signal) as any;
    assert.equal(staged.sha256, createHash('sha256').update('{"proposal":true}').digest('hex'));
    assert.ok(staged.artifact_ref.startsWith(acquired.binding.work.candidate_namespace + '/'));
    assert.throws(() => validateProposal({ ...proposed(acquired.binding, staged.artifact_ref), quality: 'EXACT' }, acquired.binding), /INVALID_PROPOSAL_SCHEMA/);
    await assert.rejects(domain.commitProposal(acquired.binding, acquired.lease, { ...proposed(acquired.binding, staged.artifact_ref), quality: 'EXACT' } as any), /INVALID_CONTRACT/);
    await assert.rejects(domain.commitProposal(acquired.binding, acquired.lease, proposed(acquired.binding, `${acquired.binding.work.candidate_namespace}/nonexistent`)), /ARTIFACT/);
    // Corrupt the real CAS object, then ensure the trusted server rejects hash drift.
    const objectPath = join(f.stateDir, 'artifacts', 'objects', first.sha256.slice(0, 2), first.sha256);
    const saved = await readFile(objectPath); await chmod(objectPath, 0o600); await writeFile(objectPath, Buffer.alloc(saved.length));
    await assert.rejects(domain.readEvidence(acquired.binding, f.evidence.artifact_ref, undefined, signal), /INVALID_CONTRACT/);
    await writeFile(objectPath, saved); await chmod(objectPath, 0o444);
    await domain.releaseWorker(acquired.binding, acquired.lease);
  } finally { await domain.close(); await f.dispose(); }
});

test('two real Python processes share 32 slots; the 33rd task stays ready and acquires after confirmed cleanup', async () => {
  const f = await fixture(33); const first = f.client(); const second = f.client(); const signal = new AbortController().signal;
  try {
    const acquired = await Promise.all(f.plan.tasks.slice(0, 32).map((task, index) => (index % 2 ? second : first).tryAcquireWorker(task, signal)));
    assert.equal(acquired.filter(Boolean).length, 32);
    assert.equal(new Set(acquired.map(item => item!.binding.work.attempt_id)).size, 32);
    assert.equal(await second.tryAcquireWorker(f.plan.tasks[32]!, signal), null);
    assert.equal((await f.setup.call('task.get', { task_id: f.plan.tasks[32]!.task_id })).state, 'READY');
    await first.releaseWorker(acquired[0]!.binding, acquired[0]!.lease);
    const queued = await second.tryAcquireWorker(f.plan.tasks[32]!, signal); assert.ok(queued);
    for (let index = 1; index < acquired.length; index++) await (index % 2 ? second : first).releaseWorker(acquired[index]!.binding, acquired[index]!.lease);
    await second.releaseWorker(queued.binding, queued.lease);
  } finally { await first.close(); await second.close(); await f.dispose(); }
});

test('real Job cancellation fences both injected pending activations and releases only after disposal', async () => {
  const f = await fixture(2); const domain = f.client();
  try {
    const provider = new InjectedProvider(domain);
    provider.hook = request => new Promise(resolveResult => request.signal.addEventListener('abort', () => resolveResult({ output: [], stopReason: 'aborted' }), { once: true }));
    const runner = new BatchRunner(domain, provider, 1000); const running = runner.runBatch(f.plan.batch_ref, f.plan.job_id, parent);
    while (provider.starts.length !== 2) await tick();
    await runner.cancel(f.plan.job_id); const result = await running;
    assert.deepEqual(result.workers.map(worker => worker.state), ['CANCELLED', 'CANCELLED']);
    assert.equal(provider.disposed.length, 2);
    for (const request of provider.starts) assert.equal(await domain.receipt(request.binding.execution_key), null);
    assert.equal((await f.setup.call('job.get', { job_id: f.plan.job_id })).execution_state, 'CANCELLED');
  } finally { await domain.close(); await f.dispose(); }
});

test('aborting a blocked real SQLite read reaps its RPC process and durably fences all owned worker identities', async () => {
  const f = await fixture(1); const domain = f.client(); const signal = new AbortController().signal;
  let lock: ReturnType<typeof spawn> | undefined;
  try {
    const acquired = (await domain.tryAcquireWorker(f.plan.tasks[0]!, signal))!;
    await domain.bindActivation(acquired.binding, acquired.lease, { session_id: 'blocked-read', activation_id: 'blocked-activation' });
    lock = spawn(python, ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("BEGIN IMMEDIATE"); print("ready",flush=True); sys.stdin.readline(); c.rollback()', join(f.stateDir, 'domain.sqlite3')], { stdio: ['pipe', 'pipe', 'pipe'] });
    await new Promise<void>(yes => lock!.stdout!.once('data', () => yes()));
    const controller = new AbortController();
    const read = domain.readContract(acquired.binding, controller.signal);
    await delay(20); controller.abort();
    await delay(50); lock.stdin!.end('\n');
    await assert.rejects(read, /RPC_ABORTED/);
    assert.equal(await domain.confirmToolCleanup(acquired.binding, acquired.lease), false);
    await assert.rejects(domain.commitProposal(acquired.binding, acquired.lease, proposed(acquired.binding, `${acquired.binding.work.candidate_namespace}/fake`)), /WORKER_FENCED/);
    const task = await f.setup.call('task.get', { task_id: f.plan.tasks[0]!.task_id }); assert.equal(task.state, 'RETRYABLE');
  } finally { lock?.kill('SIGKILL'); await domain.close(); await f.dispose(); }
});

test('authenticated host socket grants only the real root batch and rejects missing or wrong capabilities', async () => {
  const { AuthenticatedLocalHost } = await import('../src/host.js');
  const { createConnection } = await import('node:net');
  const f = await fixture(1); const domain = f.client(); const secret = randomUUID() + randomUUID();
  const socketPath = join(f.stateDir, 'control', 'host.sock');
  const host = new AuthenticatedLocalHost(socketPath, secret, domain, () => domain.inspectProfile());
  const control = (token: string, method: string, params: object) => new Promise<any>((yes, no) => {
    const socket = createConnection(socketPath); let reply = '';
    socket.setTimeout(2000, () => socket.destroy(new Error('CONTROL_TEST_TIMEOUT')));
    socket.on('error', no); socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(JSON.stringify({ token, method, params }) + '\n'));
    socket.on('data', chunk => { reply += chunk; }); socket.on('end', () => yes(JSON.parse(reply)));
  });
  try {
    await host.listen();
    assert.equal(await host.authorizeRoot('real-root'), undefined);
    assert.equal((await control('wrong', 'authorize_root', { session_id: 'real-root', ...f.plan })).error.code, 'CONTROL_REJECTED');
    const authorized = await control(secret, 'authorize_root', { session_id: 'real-root', job_id: f.plan.job_id, batch_ref: f.plan.batch_ref });
    assert.equal(authorized.result.authorized, true);
    assert.deepEqual(await host.authorizeRoot('real-root'), { job_id: f.plan.job_id, batch_ref: f.plan.batch_ref });
    assert.equal((await control(secret, 'authorize_root', { session_id: 'other-root', job_id: 'foreign-job', batch_ref: f.plan.batch_ref })).error.code, 'CONTROL_REJECTED');
    await domain.auditTool(undefined, { session_id: 'real-root', job_id: f.plan.job_id, batch_ref: f.plan.batch_ref, name: 'get_recovery_batch', is_error: false });
    const stop = host.installControl(jobId => domain.cancelJob(jobId));
    assert.equal((await control(secret, 'cancel', { job_id: 'foreign-job' })).error.code, 'CONTROL_REJECTED');
    assert.equal((await control(secret, 'cancel', { job_id: f.plan.job_id })).result.cancelled, true);
    stop();
  } finally { await host.close(); await domain.close(); await f.dispose(); }
});

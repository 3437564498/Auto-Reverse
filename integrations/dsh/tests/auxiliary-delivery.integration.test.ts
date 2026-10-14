import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setImmediate as tick } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import type { ToolCallId } from '@deepseek-ai/dsh-llm';
import { createScope } from '@deepseek-ai/dsh-scope';
import { SessionId } from '@deepseek-ai/dsh-session';
import type { SubagentResult } from '@deepseek-ai/dsh-subagent';
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt';
import { defineTool, ToolRuntime } from '@deepseek-ai/dsh-tools';
import { Ajv } from 'ajv';
import { BatchRunner } from '../src/batch-runner.js';
import { DSH_COMMIT, type ActivationHandle, type ActivationProvider, type ActivationRequest, type AttemptBinding, type BatchPlan, type ProfileReport, type Proposal, type WorkPackageSpec } from '../src/contracts.js';
import { StaticPolicy } from '../src/policy.js';
import { validateProposal } from '../src/proposal.js';
import { PythonDomainClient } from '../src/python-domain-client.js';

const repository = fileURLToPath(new URL('../../../../', import.meta.url));
const python = process.env.AUTO_REVERSE_PYTHON ?? join(repository, '.venv/bin/python');
const parent = { id: SessionId('auxiliary-fixture-root') } as Agent;
// Genuine subprocess, SQLite and CAS; this injected attestation is not a model
// invocation or an assertion about an inspected production Cordis profile.
const injectedProfile: ProfileReport = { dsh_commit: DSH_COMMIT, provider: 'spawn', inspected: true, max_active_subagents: 32, max_tokens_as_success: false, global_worker_limit: 32, control_channel_authenticated: true, tool_mode: 'native' };

class SetupRpc {
  private readonly child;
  private readonly pending = new Map<string, { yes: (value: any) => void; no: (error: Error) => void }>();
  private next = 0;
  constructor(stateDir: string) {
    this.child = spawn(python, ['-m', 'auto_reverse.cli', '--state-dir', stateDir, 'domain-rpc'], { cwd: repository, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stderr.resume();
    createInterface({ input: this.child.stdout }).on('line', line => {
      const response = JSON.parse(line); const entry = this.pending.get(response.id)!; this.pending.delete(response.id);
      if (response.error) entry.no(new Error(response.error.code)); else entry.yes(response.result);
    });
    this.child.once('close', () => {
      for (const entry of this.pending.values()) entry.no(new Error('SETUP_RPC_CLOSED'));
      this.pending.clear();
    });
  }
  call(method: string, params: object): Promise<any> {
    return new Promise((yes, no) => { const id = String(++this.next); this.pending.set(id, { yes, no }); this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n'); });
  }
  async close(): Promise<void> {
    const closed = new Promise<void>(yes => this.child.once('close', () => yes()));
    this.child.stdin.end(); await closed;
  }
}

function proposal(binding: AttemptBinding, artifactRef: string, evidenceRef: string): Proposal {
  const w = binding.work;
  return { schema_version: 1, job_id: w.job_id, task_id: w.task_id, attempt_id: w.attempt_id, input_snapshot_id: w.input_snapshot_id, contract_revision: w.contract_revision, disposition: 'PROPOSED', artifact_refs: [artifactRef], evidence_refs: [evidenceRef], assumptions: [], gaps: ['infrastructure fixture; no model acceptance or trusted contract freeze'], requested_followup_tasks: [] };
}

test('real Python bridge records type_abi and evidence envelopes using their leased delivery schemas without upgrading quality', { timeout: 60_000 }, async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'dsh-auxiliary-'));
  const setup = new SetupRpc(stateDir);
  const client = () => new PythonDomainClient({ python, repository, stateDir, inspectProfile: async () => structuredClone(injectedProfile) });
  const domain = client();
  try {
    const input = await setup.call('input.register', { content: 'infrastructure-only immutable input; not a target library' });
    const policy = await setup.call('policy.register', {});
    const job = await setup.call('job.submit', { input_ref: input.input_ref, policy_ref: policy.policy_ref, idempotency_key: randomUUID() });
    const evidence = await setup.call('evidence.register', { value: { fixture: 'no embedded DWARF; declaration verification is intentionally not attempted' } });
    const taskIds: string[] = [];
    for (const role of ['type_abi', 'evidence'] as const) {
      const taskId = `auxiliary-${role}`; taskIds.push(taskId);
      const manifest = await setup.call('manifest.create', { job_id: job.job_id, task_id: taskId, artifact_refs: [evidence.artifact_ref] });
      const work: WorkPackageSpec = { schema_version: 1, job_id: job.job_id, task_id: taskId, role, scope: { function_ids: ['auxiliary_fn'], region_ids: [] }, input_snapshot_id: job.input_snapshot_id, contract_revision: job.contract_revision, dependencies: [], evidence_manifest_ref: manifest.evidence_manifest_ref, candidate_namespace: `candidate://${job.job_id}/${taskId}`, allowed_operations: ['evidence_read', 'contract_read', 'candidate_submit', 'task_report'], limits: { wall_timeout_seconds: 30, max_tool_calls: 80, max_agent_depth: 1 }, stop_conditions: ['proposal_submitted'], missing_evidence_policy: 'report_gap' };
      await setup.call('task.create', { work_package: work });
    }
    const batch = await setup.call('batch.create', { job_id: job.job_id, task_ids: taskIds, idempotency_key: randomUUID() });
    const plan = await domain.loadBatch(batch.batch_ref) as BatchPlan;
    const before = await setup.call('job.get', { job_id: job.job_id });
    const requests: ActivationRequest[] = []; const identities: string[] = []; const disposed: string[] = [];
    const payloads: { sha256: string; content: string }[] = []; const workerErrors: unknown[] = [];
    const provider: ActivationProvider = {
      name: 'spawn',
      capabilities: () => ({ fresh: true, local: true, agentOptions: true, outputSchema: true, depthLimit: true, persona: true, toolFilter: true }),
      async startActivation(request): Promise<ActivationHandle> {
        requests.push(request); const sessionId = `auxiliary-session-${randomUUID()}`; identities.push(sessionId);
        const result = (async (): Promise<SubagentResult> => {
          const contract = await domain.readContract(request.binding, request.signal) as any;
          const role = request.binding.work.role;
          assert.equal(contract.work.attempt_id, request.binding.work.attempt_id);
          assert.equal(contract.work.role, role);
          assert.equal(contract.expected_delivery_kind, role === 'type_abi' ? 'scalar_abi_constraints' : 'scoped_evidence_or_diagnostic');
          assert.equal(contract.abi_contracts.job_id, job.job_id);
          assert.equal(contract.abi_contracts.contract_revision, job.contract_revision);
          assert.deepEqual(contract.abi_contracts.current_contracts, []);
          assert.equal(contract.abi_contracts.current_valid, false);
          assert.equal(contract.abi_contracts.original_calling_abi_verified, false);
          assert.equal(contract.abi_contracts.job_quality_promoted, false);
          const delivered = await domain.readEvidence(request.binding, evidence.artifact_ref, undefined, request.signal) as any;
          assert.equal(delivered.complete, true); assert.equal(delivered.offset, 0);
          assert.equal(delivered.returned, delivered.total);
          const envelope = role === 'type_abi'
            ? { schema_version: 1, kind: 'scalar_abi_constraints', symbol: 'auxiliary_fn', parameter_widths: [32, 64], return_width: 64 }
            : { schema_version: 1, kind: 'evidence_gap', symbol: 'auxiliary_fn', findings: [], gaps: ['The delivered fixture provides no original declaration evidence.'], evidence_refs: [evidence.artifact_ref] };
          const schema = role === 'type_abi' ? contract.scalar_abi_constraints_contract : contract.evidence_delivery_contract;
          const valid = new Ajv({ allErrors: true, strict: true }).compile(schema);
          assert.equal(valid(envelope), true, JSON.stringify(valid.errors));
          assert.equal(valid({ ...envelope, quality: 'EXACT' }), false);
          assert.equal(valid({ schema_version: 1, kind: 'cpp_source', symbol: 'auxiliary_fn', source: 'fake source' }), false);
          const content = JSON.stringify(envelope);
          const staged = await domain.stageCandidate(request.binding, `${role}.json`, content, request.signal) as any;
          assert.equal(staged.sha256, createHash('sha256').update(content).digest('hex'));
          assert.ok(staged.artifact_ref.startsWith(request.binding.work.candidate_namespace + '/'));
          payloads.push({ sha256: staged.sha256, content });
          return { output: [], stopReason: 'completed', structured: validateProposal(proposal(request.binding, staged.artifact_ref, evidence.artifact_ref), request.binding) };
        })().catch(error => { workerErrors.push(error); throw error; });
        return { session_id: sessionId, activation_id: `auxiliary-activation-${randomUUID()}`, result, dispose: async () => { disposed.push(request.binding.work.attempt_id); } };
      },
    };
    const outcome = await new BatchRunner(domain, provider).runBatch(plan.batch_ref, plan.job_id, parent);
    if (workerErrors.length) throw workerErrors[0];
    assert.deepEqual(outcome.workers.map(worker => worker.state), ['RECORDED', 'RECORDED']);
    assert.equal(new Set(identities).size, 2); assert.equal(new Set(disposed).size, 2);
    const receipts = [];
    for (const request of requests) {
      receipts.push(await domain.receipt(request.binding.execution_key));
      assert.equal(receipts.at(-1)?.disposition, 'RECORDED');
      assert.equal((await setup.call('task.get', { task_id: request.binding.work.task_id })).state, 'RESULT_PROPOSED');
    }
    for (const payload of payloads) {
      assert.equal(await readFile(join(stateDir, 'artifacts', 'objects', payload.sha256.slice(0, 2), payload.sha256), 'utf8'), payload.content);
    }
    const after = await setup.call('job.get', { job_id: job.job_id });
    assert.deepEqual(after.quality, before.quality);
    assert.equal(after.contract_revision, before.contract_revision);
    await domain.close();
    const restarted = client();
    try {
      assert.deepEqual(await restarted.loadBatch(plan.batch_ref), plan);
      for (let index = 0; index < requests.length; index++) assert.deepEqual(await restarted.receipt(requests[index]!.binding.execution_key), receipts[index]);
    } finally { await restarted.close(); }
  } finally { await domain.close(); await setup.close(); await rm(stateDir, { recursive: true, force: true }); }
});

test('official Cordis auxiliary worker scopes deny host consumption, ABI freeze and quality tools even when registered locally', async () => {
  const rootContext = new Context();
  const promptFiber = rootContext.plugin(SystemPrompt, {});
  const toolsFiber = rootContext.plugin(ToolRuntime, { mode: 'native' });
  await tick();
  let ready!: (ctx: Context) => void;
  const contextReady = new Promise<Context>(resolve => { ready = resolve; });
  const testFiber = rootContext.inject(['tools'], ctx => { ready(ctx); });
  const ctx = await contextReady;
  const scopes: ReturnType<typeof createScope>[] = [];
  const policy = new StaticPolicy();
  let hostMutationCalls = 0;
  const tool = (name: string, mutation = false) => defineTool({ name, description: 'Auxiliary worker registry fixture.', parameters: {}, output: { schema: { type: 'boolean' }, render: value => [{ type: 'text', text: String(value) }] }, execute: async () => { if (mutation) hostMutationCalls += 1; return true; } });
  ctx.tools.guard(exec => policy.deny(exec.agent, exec.name));
  try {
    for (const role of ['type_abi', 'evidence'] as const) {
      const worker = { id: SessionId(`auxiliary-${role}`) } as Agent;
      const binding: AttemptBinding = { epoch: 1, execution_key: `fixture-${role}`, work: { schema_version: 1, job_id: 'job', task_id: `task-${role}`, attempt_id: `attempt-${role}`, role, scope: { function_ids: ['auxiliary_fn'], region_ids: [] }, input_snapshot_id: 'snapshot', contract_revision: 1, evidence_manifest_ref: 'evidence://job/auxiliary', candidate_namespace: `candidate://job/task-${role}/attempt-${role}`, dependencies: [], allowed_operations: ['evidence_read', 'contract_read', 'candidate_submit', 'task_report'], limits: { wall_timeout_seconds: 30, max_tool_calls: 80, max_agent_depth: 1 }, stop_conditions: [], missing_evidence_policy: 'report_gap' } };
      policy.bindWorker(worker, binding);
      const scope = createScope(ctx, worker); scopes.push(scope);
      scope.ctx.tools.restrict({ allow: [] });
      const allowed = ['evidence_read', 'contract_read', 'candidate_stage', 'task_report', 'structured_output'];
      for (const name of allowed) scope.ctx.tools.register(tool(name));
      const schemas = ctx.tools.schemas(worker).map(entry => entry.name);
      assert.deepEqual(schemas, allowed); policy.assertSurface(worker, schemas);
      for (const name of ['consume_evidence_delivery', 'freeze_abi_contract', 'postprocess_candidates', 'record_quality']) {
        scope.ctx.tools.register(tool(name, true));
        const result = await ctx.tools.execute({ callId: `${role}-${name}` as ToolCallId, name, arguments: {}, agent: worker, signal: new AbortController().signal });
        assert.equal(result.isError, true);
      }
      assert.throws(() => policy.assertSurface(worker, ctx.tools.schemas(worker).map(entry => entry.name)), /UNSAFE_EFFECTIVE_TOOL_SURFACE/);
      assert.equal(policy.deny({ id: worker.id } as Agent, 'contract_read'), 'UNBOUND_AGENT');
    }
    assert.equal(hostMutationCalls, 0);
  } finally {
    for (const scope of scopes) await scope.dispose();
    await testFiber.dispose(); await toolsFiber.dispose(); await promptFiber.dispose();
  }
});

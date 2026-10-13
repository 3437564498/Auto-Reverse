import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate as tick } from 'node:timers/promises';
import { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { SessionId } from '@deepseek-ai/dsh-session';
import { createScope } from '@deepseek-ai/dsh-scope';
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt';
import { ToolRuntime, defineTool } from '@deepseek-ai/dsh-tools';
import type { ToolCallId } from '@deepseek-ai/dsh-llm';
import { StaticPolicy } from '../src/policy.js';
import type { AttemptBinding } from '../src/contracts.js';

// Real official Cordis/ToolRuntime registries; Agent objects below are test fixtures.
// No model, Session loop, analysis activity, input binary or candidate is run.
test('official Cordis scoped registry preserves worker own tools and monotonic guard denies scoped Shell', async () => {
  const rootContext = new Context();
  const promptFiber = rootContext.plugin(SystemPrompt, {});
  const toolsFiber = rootContext.plugin(ToolRuntime, { mode: 'native' });
  await tick();
  let ready!: (ctx: Context) => void;
  const contextReady = new Promise<Context>(resolve => { ready = resolve; });
  const testFiber = rootContext.inject(['tools'], ctx => { ready(ctx); });
  const ctx = await contextReady;
  const policy = new StaticPolicy();
  const root = { id: SessionId('root-fixture') } as Agent;
  const child = { id: SessionId('child-fixture') } as Agent;
  const rootScope = createScope(ctx, root);
  const childScope = createScope(ctx, child, { parent: root });
  policy.bindRoot(root, 'job', 'batch');
  const work: AttemptBinding = { epoch: 1, execution_key: 'execution', work: {
    schema_version: 1, job_id: 'job', task_id: 'task', attempt_id: 'attempt', role: 'reviewer', scope: { function_ids: ['fn'], region_ids: [] },
    input_snapshot_id: 'snapshot', contract_revision: 1, dependencies: [], evidence_manifest_ref: 'evidence://job/fn', candidate_namespace: 'candidate://job/attempt',
    allowed_operations: ['evidence_read', 'task_report'], limits: { wall_timeout_seconds: 30, max_tool_calls: 80, max_agent_depth: 1 }, stop_conditions: [], missing_evidence_policy: 'report_gap',
  } };
  policy.bindWorker(child, work);
  let ranShell = false;
  function tool(name: string, run: () => void = () => {}) {
    return defineTool({ name, description: 'Test fixture tool.', parameters: {}, output: { schema: { type: 'boolean' }, render: value => [{ type: 'text', text: String(value) }] }, execute: async () => { run(); return true; } });
  }
  ctx.tools.register(tool('global_shell', () => { ranShell = true; }));
  rootScope.ctx.tools.restrict({ allow: [] });
  rootScope.ctx.tools.register(tool('run_recovery_batch'));
  childScope.ctx.tools.restrict({ allow: [] });
  childScope.ctx.tools.register(tool('evidence_read'));
  childScope.ctx.tools.register(tool('structured_output'));
  ctx.tools.guard(exec => policy.deny(exec.agent, exec.name));
  // A later permissive pre-execute plugin cannot reverse the monotonic guard.
  ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }));
  assert.deepEqual(ctx.tools.schemas(root).map(tool => tool.name), ['run_recovery_batch']);
  assert.deepEqual(ctx.tools.schemas(child).map(tool => tool.name), ['evidence_read', 'structured_output']);
  const evidence = await ctx.tools.execute({ callId: 'read-1' as ToolCallId, name: 'evidence_read', arguments: {}, agent: child, signal: new AbortController().signal });
  assert.equal(evidence.isError, false);
  const structure = await ctx.tools.execute({ callId: 'output-1' as ToolCallId, name: 'structured_output', arguments: {}, agent: child, signal: new AbortController().signal });
  assert.equal(structure.isError, false);
  // Own-scope additions bypass restrict visibility, so guard must still reject execution.
  childScope.ctx.tools.register(tool('Shell', () => { ranShell = true; }));
  const shell = await ctx.tools.execute({ callId: 'shell-1' as ToolCallId, name: 'Shell', arguments: {}, agent: child, signal: new AbortController().signal });
  assert.equal(shell.isError, true); assert.equal(ranShell, false);
  assert.throws(() => policy.assertSurface(child, ctx.tools.schemas(child).map(tool => tool.name)), /UNSAFE_EFFECTIVE_TOOL_SURFACE/);
  await childScope.dispose(); await rootScope.dispose(); await testFiber.dispose(); await toolsFiber.dispose(); await promptFiber.dispose();
});

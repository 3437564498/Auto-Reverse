import type { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { defineTool } from '@deepseek-ai/dsh-tools';
import type { DomainClient, RecoveryHost } from './contracts.js';
import { BatchRunner } from './batch-runner.js';
import { NativeSpawnProvider } from './native-provider.js';
import { StaticPolicy } from './policy.js';

declare module '@deepseek-ai/cordis' {
  interface Context { recoveryDomain: DomainClient; recoveryHost: RecoveryHost }
}
export const name = 'recovery-controlled-batch';
export const inject = ['recoveryDomain', 'recoveryHost', 'agents', 'subagents', 'tools'];

const jsonOutput = { schema: { type: 'json' as const }, render: (value: unknown) => [{ type: 'text' as const, text: JSON.stringify(value) }] };

/** Real Cordis entry. Host services are intentionally mandatory and fail closed. */
export function apply(ctx: Context): void {
  const policy = new StaticPolicy();
  const domain = ctx.recoveryDomain;
  const auditWrites = new Set<Promise<void>>();
  let auditFailed = false;
  const provider = new NativeSpawnProvider(ctx, policy, agent => {
    const binding = policy.worker(agent);
    const scoped = agent.ctx;
    scoped.tools.presentAs('native');
    if (binding.work.allowed_operations.includes('evidence_read')) scoped.tools.register(defineTool({
      name: 'evidence_read', description: 'Read authorized paginated static evidence by reference. Never executes the input.',
      parameters: { ref: { type: 'string', required: true }, cursor: { type: 'string' } }, output: jsonOutput,
      isConcurrencySafe: () => true,
      execute: (args, exec) => domain.readEvidence(policy.worker(exec.agent), args.ref, args.cursor, exec.signal),
    }));
    if (binding.work.allowed_operations.includes('contract_read')) scoped.tools.register(defineTool({
      name: 'contract_read', description: 'Read this Attempt frozen contract.', parameters: {}, output: jsonOutput,
      isConcurrencySafe: () => true,
      execute: (_args, exec) => domain.readContract(policy.worker(exec.agent), exec.signal),
    }));
    if (binding.work.allowed_operations.includes('task_report')) scoped.tools.register(defineTool({
      name: 'task_report', description: 'Report a bounded evidence gap, block or lack of progress; never sets semantic quality.',
      parameters: { reason: { type: 'string', enum: ['NEEDS_EVIDENCE', 'BLOCKED', 'NO_PROGRESS'], required: true }, details: { type: 'string', required: true } },
      output: jsonOutput,
      execute: (args, exec) => domain.reportTask(policy.worker(exec.agent), args.reason, args.details, exec.signal),
    }));
  });
  const runner = new BatchRunner(domain, provider);
  ctx.tools.guard(exec => {
    if (exec.agent === undefined || ctx.agents.get(exec.agent.id) !== exec.agent) return 'NOT_EXACT_LIVE_AGENT';
    return auditFailed ? 'AUDIT_UNAVAILABLE' : policy.deny(exec.agent, exec.name);
  });
  ctx.on('agent/created', async ({ agent }) => {
    if (policy.get(agent)?.kind === 'worker') return;
    const authorization = await ctx.recoveryHost.authorizeRoot(agent.id);
    if (authorization === undefined) throw new Error('ROOT_NOT_AUTHORIZED');
    policy.bindRoot(agent, authorization.job_id, authorization.batch_ref);
    agent.ctx.tools.presentAs('native');
    // Own-scope tools remain visible while all inherited global tools are hidden.
    agent.ctx.tools.restrict({ allow: [] });
    agent.ctx.tools.register(defineTool({
      name: 'run_recovery_batch', description: 'Run this root frozen, service-authorized batch. Each worker receives one fresh package.',
      parameters: { batch_ref: { type: 'string', required: true } }, output: jsonOutput,
      execute: async (args, exec) => {
        const agent = exactAgent(ctx, exec.agent);
        const binding = policy.get(agent);
        if (binding?.kind !== 'root' || binding.batch_ref !== args.batch_ref) throw new Error('BATCH_NOT_AUTHORIZED');
        const outcome = await runner.runBatch(args.batch_ref, binding.job_id, agent);
        return { job_id: outcome.job_id, batch_ref: outcome.batch_ref, workers: outcome.workers.map(worker => ({ ...worker })) };
      },
    }));
    agent.ctx.tools.register(defineTool({
      name: 'get_recovery_batch', description: 'Read compact local batch execution status, separate from Domain quality results.',
      parameters: {}, output: jsonOutput, isConcurrencySafe: () => true,
      execute: async (_args, exec) => {
        const binding = policy.get(exactAgent(ctx, exec.agent));
        const current = runner.current();
        if (binding?.kind !== 'root' || (current !== undefined && current.job_id !== binding.job_id)) throw new Error('UNAUTHORIZED_BATCH');
        return current === undefined ? { active: false } : { active: true, ...current };
      },
    }));
    policy.assertSurface(agent, agent.ctx.tools.schemas(agent).map(tool => tool.name));
  });
  ctx.on('tools/result', (exec, result) => {
    if (exec.agent === undefined) return;
    const binding = policy.get(exec.agent);
    const write = domain.auditTool(binding?.kind === 'worker' ? binding.attempt : undefined, { session_id: exec.agent.id, name: exec.name, is_error: result.isError });
    auditWrites.add(write);
    void write.then(() => auditWrites.delete(write), () => { auditWrites.delete(write); auditFailed = true; });
  });
  ctx.effect(() => {
    const stopControl = ctx.recoveryHost.installControl(jobId => runner.cancel(jobId));
    return async () => {
      stopControl();
      const current = runner.current();
      if (current !== undefined) await runner.cancel(current.job_id);
      await Promise.allSettled(auditWrites);
    };
  }, 'recovery authenticated control and drain');
}

function exactAgent(ctx: Context, agent: Agent | undefined): Agent {
  if (agent === undefined || ctx.agents.get(agent.id) !== agent) throw new Error('NOT_EXACT_LIVE_AGENT');
  return agent;
}

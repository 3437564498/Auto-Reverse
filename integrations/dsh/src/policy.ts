import type { Agent } from '@deepseek-ai/dsh-agent';
import type { AttemptBinding, Role } from './contracts.js';

const BASE = ['evidence_read', 'contract_read', 'task_report', 'candidate_stage', 'structured_output'] as const;
const ROLE_ALLOW: Record<Role, readonly string[]> = {
  planning: BASE, evidence: BASE, type_abi: BASE, recovery: BASE, reviewer: BASE,
  repair: BASE, integration: BASE, naming: BASE, reporting: BASE,
};
const OPERATIONS: Record<string, string> = {
  evidence_read: 'evidence_read', contract_read: 'contract_read', task_report: 'task_report',
  candidate_stage: 'candidate_submit', structured_output: 'candidate_submit',
};
export type AgentBinding = { kind: 'root'; job_id: string; batch_ref: string } | { kind: 'worker'; attempt: AttemptBinding; active: boolean; calls: number };

/** Authorization keys on the exact live Agent object; ID/role arguments grant nothing. */
export class StaticPolicy {
  private readonly bindings = new WeakMap<Agent, AgentBinding>();
  bindRoot(agent: Agent, job_id: string, batch_ref: string): void { this.bindings.set(agent, { kind: 'root', job_id, batch_ref }); }
  bindWorker(agent: Agent, attempt: AttemptBinding): void { this.bindings.set(agent, { kind: 'worker', attempt, active: true, calls: 0 }); }
  get(agent: Agent | undefined): AgentBinding | undefined { return agent === undefined ? undefined : this.bindings.get(agent); }
  deactivate(agent: Agent): void {
    const binding = this.get(agent);
    if (binding?.kind === 'worker') binding.active = false;
  }
  worker(agent: Agent | undefined): AttemptBinding {
    const binding = this.get(agent);
    if (binding?.kind !== 'worker' || !binding.active) throw new Error('UNAUTHORIZED_ATTEMPT');
    return binding.attempt;
  }
  deny(agent: Agent | undefined, name: string): string | undefined {
    const binding = this.get(agent);
    if (binding === undefined) return 'UNBOUND_AGENT';
    if (binding.kind === 'root') return ['run_recovery_batch', 'get_recovery_batch'].includes(name) ? undefined : 'ROOT_TOOL_DENIED';
    if (!binding.active) return 'INACTIVE_ATTEMPT';
    if (!ROLE_ALLOW[binding.attempt.work.role]?.includes(name)) return 'STATIC_TOOL_DENIED';
    const operation = OPERATIONS[name];
    if (operation === undefined || !binding.attempt.work.allowed_operations.includes(operation)) return 'OPERATION_DENIED';
    if (binding.calls >= binding.attempt.work.limits.max_tool_calls) return 'TOOL_BUDGET_EXCEEDED';
    binding.calls += 1;
    return undefined;
  }
  /** Check effective schemas without consuming the execution budget. */
  assertSurface(agent: Agent, names: readonly string[]): void {
    const binding = this.get(agent);
    const allowed = binding?.kind === 'root' ? ['run_recovery_batch', 'get_recovery_batch'] : binding?.kind === 'worker' ? ROLE_ALLOW[binding.attempt.work.role] : [];
    if (names.some(name => !allowed.includes(name))) throw new Error('UNSAFE_EFFECTIVE_TOOL_SURFACE');
  }
}

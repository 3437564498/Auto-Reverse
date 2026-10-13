import { randomUUID } from 'node:crypto';
import type { Context } from '@deepseek-ai/cordis';
import type { Agent } from '@deepseek-ai/dsh-agent';
import { SessionId } from '@deepseek-ai/dsh-session';
import type { SubagentRunInfo } from '@deepseek-ai/dsh-subagent';
import type { ActivationHandle, ActivationProvider, ActivationRequest } from './contracts.js';
import { frozenPrompt } from './proposal.js';
import type { StaticPolicy } from './policy.js';

/** Wraps the pinned official startActivation; no invented SDK RPC or handle ID. */
export class NativeSpawnProvider implements ActivationProvider {
  readonly name = 'spawn';
  private readonly pending = new Map<string, { request: ActivationRequest; runId?: string; agent?: Agent }>();
  constructor(private readonly ctx: Context, private readonly policy: StaticPolicy, private readonly composeWorker: (agent: Agent) => void) {
    ctx.on('agent/created', ({ agent }) => {
      const pending = this.pending.get(agent.id);
      if (pending === undefined) return;
      if (this.ctx.agents.get(agent.id) !== agent) throw new Error('NOT_EXACT_LIVE_AGENT');
      pending.agent = agent;
      policy.bindWorker(agent, pending.request.binding);
      composeWorker(agent);
      policy.assertSurface(agent, agent.ctx.tools.schemas(agent).map(tool => tool.name));
    });
    ctx.on('subagent/start', (info: SubagentRunInfo) => {
      const pending = this.pending.get(info.id);
      if (pending === undefined) return;
      if (!info.local || info.provider !== this.name || pending.agent !== this.ctx.agents.get(info.id)) throw new Error('INVALID_ACTIVATION_PUBLICATION');
      pending.runId = info.runId;
    });
    ctx.on('agent/disposed', ({ agent }) => { policy.deactivate(agent); });
  }
  capabilities() {
    const provider = this.ctx.subagents.getProvider(this.name);
    if (provider === undefined) throw new Error('SPAWN_PROVIDER_UNAVAILABLE');
    return { ...provider.capabilities, fresh: !provider.inheritsParentContext, local: provider.prepareContinuable !== undefined };
  }
  async startActivation(request: ActivationRequest): Promise<ActivationHandle> {
    const childId = SessionId(`recovery-${randomUUID()}`);
    const pending: { request: ActivationRequest; runId?: string; agent?: Agent } = { request };
    this.pending.set(childId, pending);
    try {
      const activation = await this.ctx.subagents.startActivation({
        provider: this.name, childId, label: request.binding.work.task_id,
        signal: request.signal, delivery: request.delivery,
        request: { parent: request.parent, prompt: [{ type: 'text', text: frozenPrompt(request.binding) }],
          outputSchema: request.outputSchema, maxDepth: request.maxDepth, toolFilter: request.toolFilter,
          persona: request.persona, agentOptions: { ...request.parent.options },
        },
      });
      // Guard against an incompatible implementation silently omitting lifecycle publication.
      if (pending.runId === undefined || pending.agent === undefined) {
        await activation.dispose();
        throw new Error('MISSING_REAL_ACTIVATION_BINDING');
      }
      const agent = pending.agent;
      return { session_id: activation.childId, activation_id: pending.runId, result: activation.result,
        dispose: async () => { this.policy.deactivate(agent); await activation.dispose(); },
      };
    } finally { this.pending.delete(childId); }
  }
}

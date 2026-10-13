import { readFile } from 'node:fs/promises';
import { FiberState, type Context } from '@deepseek-ai/cordis';
import { DSH_COMMIT, type ProfileReport } from './contracts.js';

/** Inspects the actual running pinned Cordis tree; absent observations remain explicit gaps. */
export async function inspectEffectiveProfile(ctx: Context, controlAuthenticated: boolean): Promise<ProfileReport> {
  const missing: string[] = [];
  for (const [name, expected] of [['@deepseek-ai/cordis', '4.0.5-alpha.1'], ['@deepseek-ai/dsh-subagent', '0.2.1-alpha.2'], ['@deepseek-ai/dsh-tools', '0.2.1-alpha.2'], ['@deepseek-ai/dsh-sdk-jsonrpc-server', '0.2.1-alpha.2']]) {
    try { const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.resolve(name!)), 'utf8')); if (manifest.version !== expected) missing.push(`package.version:${name}`); }
    catch { missing.push(`package.unobserved:${name}`); }
  }
  const fibers = [...ctx.registry.values()].flatMap(runtime => [...runtime.fibers]).filter(fiber => fiber.state === FiberState.ACTIVE);
  const subagents = ctx.get('subagents') as unknown as { config?: { maxActiveSubagents?: { get?: () => unknown } }; getProvider?: (name: string) => { inheritsParentContext?: boolean; prepareContinuable?: unknown; capabilities?: Record<string, boolean> } } | undefined;
  const provider = subagents?.getProvider?.('spawn');
  if (provider === undefined || provider.inheritsParentContext !== false || typeof provider.prepareContinuable !== 'function' || !['agentOptions', 'outputSchema', 'depthLimit', 'toolFilter', 'persona'].every(key => provider.capabilities?.[key] === true)) missing.push('subagents.spawn.fresh_local_capabilities');
  const capacity = subagents?.config?.maxActiveSubagents?.get?.();
  if (capacity !== 32) missing.push('subagents.maxActiveSubagents');
  const tools = ctx.get('tools') as unknown as { defaultMode?: unknown; schemas?: () => { name: string }[] } | undefined;
  if (tools?.defaultMode !== 'native') missing.push('tools.native');
  const sdk = fibers.filter(fiber => fiber.runtime?.name === 'sdk-jsonrpc-server');
  const maxTokens = sdk.length === 1 ? sdk[0]?.config?.maxTokensAsSuccess : undefined;
  if (maxTokens !== false) missing.push('sdk.maxTokensAsSuccess');
  const forbidden = fibers.filter(fiber => /(?:tool-bash|tool-pwsh|terminal-bash|workflow|tool-subagent|plugin-management|plugin-install|tool-run-code|ptc-runtime)/i.test(fiber.name));
  if (forbidden.length) missing.push('plugins.forbidden_active');
  if (tools?.schemas?.().some(tool => !['structured_output'].includes(tool.name))) missing.push('tools.unexpected_global_surface');
  if (!controlAuthenticated) missing.push('control.authenticated_local_socket');
  // The commit denotes the package/source compatibility baseline, never a model-run claim.
  return { dsh_commit: DSH_COMMIT, provider: provider === undefined ? 'missing' : 'spawn', inspected: missing.length === 0,
    missingPreflight: missing, max_active_subagents: typeof capacity === 'number' ? capacity : 0,
    max_tokens_as_success: maxTokens !== false, global_worker_limit: 32,
    control_channel_authenticated: controlAuthenticated, tool_mode: tools?.defaultMode === 'native' ? 'native' : tools?.defaultMode === 'ptc' ? 'ptc' : 'unobserved' };
}

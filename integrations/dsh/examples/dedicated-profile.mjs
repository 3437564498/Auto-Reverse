import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Complete private profile tree; no inheritance from sdk/sdk-minimal or user DSH home. */
export async function materializeDedicatedProfile({ runtimeDir, repository, stateDir, python, tokenFile, socketPath, withModel = false }) {
  const dshHome = join(resolve(runtimeDir), 'dsh-home');
  const dir = join(dshHome, 'profiles', 'recovery-controlled');
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const row = (id, name, config = {}) => ({ id, name, config });
  const tree = [
    row('sdk-app', '@deepseek-ai/dsh-sdk-app', { profile: 'recovery-controlled' }),
    { ...row('sdk-server', '@deepseek-ai/dsh-sdk-jsonrpc-server', { maxTokensAsSuccess: false }), inject: ['sdkAppStartup', 'loader'] },
    row('timer', '@deepseek-ai/cordis-plugin-timer'),
    row('llm', '@deepseek-ai/dsh-llm'),
    row('session', '@deepseek-ai/dsh-session'),
    row('projection', '@deepseek-ai/dsh-session-projection'),
    row('filesystem', '@deepseek-ai/dsh-fs-local'),
    row('system-prompt', '@deepseek-ai/dsh-system-prompt', { includeHarnessIdentity: false, includeRuntimeContext: false, personaPrefix: 'Run only your host-authorized recovery batch using native tools. Never execute binaries or claim independent equivalence.' }),
    row('working-directory', '@deepseek-ai/dsh-working-directory', { defaultDirectory: resolve(repository) }),
    row('tools', '@deepseek-ai/dsh-tools', { mode: 'native' }),
    row('agents', '@deepseek-ai/dsh-agent'),
    row('jobs', '@deepseek-ai/dsh-jobs-local'),
    row('agent-loop', '@deepseek-ai/dsh-agent-loop', { agents: [] }),
    row('sessions', '@deepseek-ai/dsh-session-persistence-jsonl', { root: join(dshHome, 'sessions'), compression: 'none' }),
    row('subagents', '@deepseek-ai/dsh-subagent', { maxActiveSubagents: 32, maxDepth: 1 }),
    row('spawn', '@deepseek-ai/dsh-subagent-spawn-in-process', { providerName: 'spawn' }),
    row('python-host', fileURLToPath(new URL('../dist/src/host-plugin.js', import.meta.url)), { python: python.includes('/') ? resolve(python) : python, repository: resolve(repository), stateDir: resolve(stateDir), controlSocket: resolve(socketPath), controlTokenFile: resolve(tokenFile), rpcTimeoutMs: 30_000 }),
    row('recovery-batch', fileURLToPath(new URL('../dist/src/plugin.js', import.meta.url))),
  ];
  if (withModel) tree.splice(3, 0, row('deepseek-provider', '@deepseek-ai/dsh-llm-deepseek-api-key', { apiKeyEnv: 'DEEPSEEK_API_KEY' }));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'dsh-profile-recovery-controlled', private: true, dependencies: {}, dsh: { profile: { bundles: [] } } }, null, 2));
  await writeFile(join(dir, 'cordis.patch.yml'), JSON.stringify([{ insert: tree }], null, 2));
  return { dshHome, profile: 'recovery-controlled', pluginNames: tree.map(item => item.name) };
}

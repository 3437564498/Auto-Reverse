import { DeepSeekHarness } from '@deepseek-ai/dsh-sdk-client';
import { createConnection } from 'node:net';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { materializeDedicatedProfile } from './dedicated-profile.mjs';

export function control(socketPath, secret, method, params = {}) {
  return new Promise((yes, no) => {
    const socket = createConnection(socketPath); let reply = '';
    socket.setTimeout(15_000, () => { socket.destroy(); no(new Error('CONTROL_TIMEOUT')); });
    socket.on('error', () => no(new Error('CONTROL_UNAVAILABLE')));
    socket.on('connect', () => socket.write(JSON.stringify({ token: secret, method, params }) + '\n'));
    socket.setEncoding('utf8'); socket.on('data', chunk => { reply += chunk; });
    socket.on('end', () => { try { const response = JSON.parse(reply); if (response.error) throw new Error('CONTROL_REJECTED'); yes(response.result); } catch { no(new Error('CONTROL_REJECTED')); } });
  });
}

/** Offline performs real SDK startup/config inspection and zero model calls. */
export async function launchAuthorizedBatch({ runtimeDir, repository, stateDir, python, jobId, batchRef, provider = 'deepseek-official', model = 'deepseek-v4-flash', env = process.env, realModel = false }) {
  if (realModel && (!env.DEEPSEEK_API_KEY || !jobId || !batchRef)) throw new Error('REAL_MODEL_REQUIRES_KEY_AND_FROZEN_BATCH');
  await mkdir(resolve(runtimeDir), { recursive: true, mode: 0o700 });
  const socketPath = join(resolve(runtimeDir), 'control.sock');
  const tokenFile = join(resolve(runtimeDir), 'control.token'); const secret = randomBytes(32).toString('hex');
  await writeFile(tokenFile, secret + '\n', { mode: 0o600, flag: 'wx' });
  const profile = await materializeDedicatedProfile({ runtimeDir, repository, stateDir, python, tokenFile, socketPath, withModel: realModel });
  const harness = new DeepSeekHarness({ ...profile, processCwd: resolve(repository), provider, model, env, maxTokens: 8192, initializeTimeoutMs: 30_000 });
  try {
    await harness.start();
    const report = await control(socketPath, secret, 'preflight');
    await writeFile(join(runtimeDir, 'preflight.json'), JSON.stringify({ ...report, model_calls_requested: realModel, m0_r_accepted: false }, null, 2));
    if (!report.inspected) throw new Error(`MISSING_PREFLIGHT:${report.missingPreflight.join(',')}`);
    if (!realModel) return { sdk_started: true, preflight: report, model_calls: 0, m0_r_accepted: false };
    const rootSessionId = `recovery-root-${randomUUID()}`;
    await control(socketPath, secret, 'authorize_root', { session_id: rootSessionId, job_id: jobId, batch_ref: batchRef });
    await harness.session(rootSessionId).run(`Run this authorized frozen batch via run_recovery_batch. batch_ref=${JSON.stringify(batchRef)}. Workers must read contract/evidence, stage a JSON candidate document through candidate_stage, and submit only PROPOSED structured output with those real artifact references. Report every missing premise as a gap. Do not execute target or candidate libraries.`);
    const receipts = await control(socketPath, secret, 'receipts', { session_id: rootSessionId });
    const recorded = receipts.filter(item => item.receipt?.disposition === 'RECORDED');
    const sessions = [...new Set(recorded.map(item => item.session_id).filter(id => typeof id === 'string' && id !== rootSessionId))];
    const activations = [...new Set(recorded.map(item => item.activation_id).filter(id => typeof id === 'string'))];
    const proof = { root_session_id: rootSessionId, child_sessions: sessions, activation_ids: activations, receipts, m0_r_accepted: false };
    await writeFile(join(runtimeDir, 'model-run-proof.json'), JSON.stringify(proof, null, 2));
    if (recorded.length < 2 || sessions.length < 2 || activations.length < 2) throw new Error('TWO_DURABLE_PROPOSALS_REQUIRED');
    return proof;
  } finally { await harness.close(); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = new Map(); for (let i = 2; i < process.argv.length; i++) { const name = process.argv[i]; args.set(name, name === '--real-model' ? true : process.argv[++i]); }
  const repository = resolve(args.get('--repository') ?? fileURLToPath(new URL('../../../', import.meta.url)));
  const runtimeDir = resolve(args.get('--runtime-dir') ?? join(repository, 'work', `dsh-runtime-${randomUUID()}`));
  try {
    const result = await launchAuthorizedBatch({ runtimeDir, repository, stateDir: resolve(args.get('--state-dir') ?? join(repository, 'work', 'dsh-domain')), python: args.get('--python') ?? join(repository, '.venv/bin/python'), jobId: args.get('--job-id'), batchRef: args.get('--batch-ref'), realModel: args.get('--real-model') === true });
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (error) { process.stderr.write((error instanceof Error && /^(?:MISSING_PREFLIGHT:|REAL_MODEL_REQUIRES_KEY_AND_FROZEN_BATCH|TWO_DURABLE_PROPOSALS_REQUIRED)/.test(error.message) ? error.message : 'SDK_HOST_FAILED') + '\n'); process.exitCode = 1; }
}

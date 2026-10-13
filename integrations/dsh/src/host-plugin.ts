import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { readFile, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { PythonDomainClient } from './python-domain-client.js';
import { AuthenticatedLocalHost } from './host.js';
import { inspectEffectiveProfile } from './profile.js';
import type {} from './plugin.js';

export const name = 'recovery-python-host';
export const provide = ['recoveryDomain', 'recoveryHost'];
export interface Config { python: string; repository: string; stateDir: string; controlSocket: string; controlTokenFile: string; rpcTimeoutMs: number }
export const Config: z<Config> = z.object({ python: z.string().required(), repository: z.string().required(), stateDir: z.string().required(), controlSocket: z.string().required(), controlTokenFile: z.string().required(), rpcTimeoutMs: z.number().min(1).default(30_000) });

/** Provides both mandatory services in the actual DSH runtime process. */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const tokenFile = resolve(config.controlTokenFile); const stat = await lstat(tokenFile);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()) throw new Error('UNSAFE_CONTROL_TOKEN_FILE');
  const secret = (await readFile(tokenFile, 'utf8')).trim();
  let host: AuthenticatedLocalHost;
  const profile = () => inspectEffectiveProfile(ctx, host?.isAuthenticated() ?? false);
  const domain = new PythonDomainClient({ python: config.python, repository: config.repository, stateDir: config.stateDir, rpcTimeoutMs: config.rpcTimeoutMs, inspectProfile: profile });
  host = new AuthenticatedLocalHost(config.controlSocket, secret, domain, () => domain.inspectProfile());
  try { await host.listen(); }
  catch (error) { await domain.close(); throw error; }
  ctx.effect(() => async () => { await host.close(); await domain.close(); }, 'recovery host socket and Python RPC');
  ctx.provide('recoveryDomain', domain);
  ctx.provide('recoveryHost', host);
}

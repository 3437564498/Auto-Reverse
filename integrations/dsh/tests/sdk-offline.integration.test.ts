import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Context } from '@deepseek-ai/cordis';
import { inspectEffectiveProfile } from '../src/profile.js';

const exec = promisify(execFile);
const repository = fileURLToPath(new URL('../../../../', import.meta.url));

test('actual SDK subprocess boots the complete dedicated Cordis profile offline and makes zero model calls', async () => {
  const runtimeDir = await mkdtemp(join(tmpdir(), 'dsh-sdk-offline-'));
  try {
    const { stdout } = await exec(process.execPath, ['examples/sdk-host.mjs', '--repository', repository, '--python', process.env.AUTO_REVERSE_PYTHON ?? join(repository, '.venv/bin/python'), '--runtime-dir', runtimeDir, '--state-dir', join(runtimeDir, 'ledger')], { cwd: join(repository, 'integrations/dsh'), timeout: 40_000, maxBuffer: 64 * 1024 });
    const proof = JSON.parse(stdout);
    assert.equal(proof.sdk_started, true); assert.equal(proof.model_calls, 0); assert.equal(proof.m0_r_accepted, false);
    assert.equal(proof.preflight.inspected, true); assert.deepEqual(proof.preflight.missingPreflight, []);
    assert.equal(proof.preflight.max_active_subagents, 32); assert.equal(proof.preflight.max_tokens_as_success, false); assert.equal(proof.preflight.tool_mode, 'native');
  } finally { await rm(runtimeDir, { recursive: true, force: true }); }
});

test('missing effective services/configuration are explicit preflight gaps rather than assumed example defaults', async () => {
  const ctx = new Context();
  const report = await inspectEffectiveProfile(ctx, false);
  assert.equal(report.inspected, false); assert.equal(report.tool_mode, 'unobserved'); assert.equal(report.max_active_subagents, 0);
  assert.ok(report.missingPreflight?.includes('sdk.maxTokensAsSuccess')); assert.ok(report.missingPreflight?.includes('control.authenticated_local_socket'));
  await ctx.fiber.dispose();
});

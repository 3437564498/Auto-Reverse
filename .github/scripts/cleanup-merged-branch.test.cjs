'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile: callbackExecFile } = require('node:child_process');
const { promisify } = require('node:util');
const { cleanupMergedBranch } = require('./cleanup-merged-branch.cjs');
const execFile = promisify(callbackExecFile);

const reviewedSha = 'a'.repeat(40);
function fixture() {
  const repo = { owner: 'example', repo: 'project' };
  const repository = { full_name: 'example/project', default_branch: 'main' };
  return {
    repo,
    payload: {
      repository,
      pull_request: {
        merged: true,
        base: { repo: { full_name: repository.full_name } },
        head: { ref: 'codex/active', sha: reviewedSha, repo: { full_name: repository.full_name } },
      },
    },
  };
}

function harness(context = fixture(), { liveSha = reviewedSha, lookupError, pushError, malformedRef } = {}) {
  const calls = [];
  const warnings = [];
  const github = {
    rest: {
      git: {
        async getRef(args) {
          calls.push(['get', args]);
          if (lookupError) throw lookupError;
          return { data: malformedRef ?? {
            ref: `refs/heads/${context.payload.pull_request.head.ref}`,
            object: { type: 'commit', sha: liveSha },
          } };
        },
      },
    },
  };
  return {
    calls,
    warnings,
    run: () => cleanupMergedBranch({ github, context, workspace: '/trusted/checkout',
      execFile: async (file, args, options) => {
        calls.push(['exec', file, args, options]);
        if (pushError) throw pushError;
        return { stdout: '', stderr: '' };
      },
      core: { info() {}, warning: (message) => warnings.push(message) },
    }),
  };
}

test('deletes only the reviewed head with exact lease argv and trusted checkout cwd', async () => {
  const h = harness();
  assert.equal(await h.run(), 'deleted');
  assert.deepEqual(h.calls, [
    ['get', { owner: 'example', repo: 'project', ref: 'heads/codex/active' }],
    ['exec', 'git', ['push', `--force-with-lease=refs/heads/codex/active:${reviewedSha}`,
      'origin', ':refs/heads/codex/active'],
    { cwd: '/trusted/checkout', timeout: 30000, maxBuffer: 65536, encoding: 'utf8' }],
  ]);
});

test('closed but unmerged PR never reads or deletes a branch', async () => {
  const context = fixture();
  context.payload.pull_request.merged = false;
  const h = harness(context);
  assert.equal(await h.run(), 'not-merged');
  assert.deepEqual(h.calls, []);
});

test('forked PR and mismatched base repository never receive deletion calls', async () => {
  for (const side of ['head', 'base']) {
    const context = fixture();
    context.payload.pull_request[side].repo.full_name = 'other/project';
    const h = harness(context);
    assert.equal(await h.run(), 'different-repository');
    assert.deepEqual(h.calls, []);
  }
});

test('main, a codex-named default branch, and other prefixes are retained without API calls', async () => {
  for (const [branch, defaultBranch] of [['main', 'main'], ['codex/stable', 'codex/stable'], ['feature/manual', 'main']]) {
    const context = fixture();
    context.payload.pull_request.head.ref = branch;
    context.payload.repository.default_branch = defaultBranch;
    const h = harness(context);
    await h.run();
    assert.deepEqual(h.calls, []);
  }
});

test('new commits after merge are retained and produce a warning', async () => {
  const h = harness(fixture(), { liveSha: 'b'.repeat(40) });
  assert.equal(await h.run(), 'changed-sha');
  assert.deepEqual(h.calls.map(([action]) => action), ['get']);
  assert.equal(h.warnings.length, 1);
});

test('missing or malformed reviewed SHA cannot authorize deletion', async () => {
  for (const sha of [undefined, '', 'not-a-commit']) {
    const context = fixture();
    context.payload.pull_request.head.sha = sha;
    const h = harness(context);
    assert.equal(await h.run(), 'missing-reviewed-sha');
    assert.deepEqual(h.calls, []);
  }
});

test('already deleted branches are idempotent and do not invoke Git', async () => {
  const h = harness(fixture(), { lookupError: { status: 404 } });
  assert.equal(await h.run(), 'already-deleted');
  assert.deepEqual(h.calls.map(([action]) => action), ['get']);
  assert.deepEqual(h.warnings, []);
});

test('protected branch rejection leaves a warning without retrying or changing protections', async () => {
  const h = harness(fixture(), { pushError: { code: 1, stderr: 'protected branch; secret diagnostic' } });
  assert.equal(await h.run(), 'push-rejected');
  assert.deepEqual(h.calls.map(([action]) => action), ['get', 'exec']);
  assert.equal(h.warnings.length, 1);
  assert.equal(h.warnings[0].includes('secret diagnostic'), false);
});

test('concurrent push after the API precheck rejects the lease without an unconditional retry', async () => {
  const h = harness(fixture(), { pushError: { code: 1, stderr: '[rejected] (stale info)' } });
  assert.equal(await h.run(), 'push-rejected');
  assert.deepEqual(h.calls.map(([action]) => action), ['get', 'exec']);
  assert.equal(h.calls[1][2][1], `--force-with-lease=refs/heads/codex/active:${reviewedSha}`);
});

test('invalid Git ref names never reach an API call or executable argument', async () => {
  for (const branch of ['codex/../main', 'codex/a.lock', 'codex/a..b', 'codex/a/',
    'codex/-option', 'codex/a@{b', 'codex/a\\b', 'codex/a:main', 'codex/a;b']) {
    const context = fixture();
    context.payload.pull_request.head.ref = branch;
    const h = harness(context);
    assert.equal(await h.run(), 'invalid-development-ref');
    assert.deepEqual(h.calls, []);
  }
});

test('lookup permission failures and unexpected ref responses never delete', async () => {
  for (const options of [{ lookupError: { status: 403 } }, { malformedRef: { ref: 'refs/heads/main' } }]) {
    const h = harness(fixture(), options);
    await h.run();
    assert.deepEqual(h.calls.map(([action]) => action), ['get']);
    assert.equal(h.warnings.length, 1);
  }
});

async function localGitFixture(t) {
  const scratch = path.join(process.cwd(), 'work', 'github-cleanup-tests');
  await fs.mkdir(scratch, { recursive: true });
  const root = await fs.mkdtemp(path.join(scratch, 'lease-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const checkout = path.join(root, 'checkout');
  const remote = path.join(root, 'remote.git');
  const git = (args) => execFile('git', args, { cwd: root, timeout: 10000, encoding: 'utf8' });
  await git(['init', '--bare', remote]);
  await git(['init', '--initial-branch=main', checkout]);
  await git(['-C', checkout, 'config', 'user.name', 'Cleanup fixture']);
  await git(['-C', checkout, 'config', 'user.email', 'cleanup@example.invalid']);
  await git(['-C', checkout, 'config', 'commit.gpgsign', 'false']);
  await git(['-C', checkout, 'remote', 'add', 'origin', remote]);
  const commit = async (content) => {
    await fs.writeFile(path.join(checkout, 'sample.txt'), content);
    await git(['-C', checkout, 'add', 'sample.txt']);
    await git(['-C', checkout, 'commit', '-m', 'Fixture update']);
    return (await git(['-C', checkout, 'rev-parse', 'HEAD'])).stdout.trim();
  };
  await commit('main\n');
  await git(['-C', checkout, 'push', 'origin', 'refs/heads/main:refs/heads/main']);
  await git(['-C', checkout, 'switch', '-c', 'codex/active']);
  const sha = await commit('reviewed\n');
  await git(['-C', checkout, 'push', 'origin', 'refs/heads/codex/active:refs/heads/codex/active']);
  const context = fixture();
  context.payload.pull_request.head.sha = sha;
  const remoteSha = (branch) => git(['--git-dir', remote, 'rev-parse', '--verify', `refs/heads/${branch}`]);
  return { checkout, context, git, commit, remoteSha, sha };
}

test('real local Git deletes the reviewed ref and preserves main', async (t) => {
  const f = await localGitFixture(t);
  const mainSha = (await f.remoteSha('main')).stdout;
  const github = { rest: { git: { getRef: async () => ({ data: {
    ref: 'refs/heads/codex/active', object: { type: 'commit', sha: f.sha },
  } }) } } };
  const warnings = [];
  assert.equal(await cleanupMergedBranch({ github, context: f.context, workspace: f.checkout,
    core: { info() {}, warning: (message) => warnings.push(message) },
  }), 'deleted');
  await assert.rejects(f.remoteSha('codex/active'));
  assert.equal((await f.remoteSha('main')).stdout, mainSha);
  assert.deepEqual(warnings, []);
});

test('real local Git retains a concurrent commit created after the API precheck', async (t) => {
  const f = await localGitFixture(t);
  let newerSha;
  const github = { rest: { git: { getRef: async () => {
    // Return the previously reviewed value, but advance the actual remote in
    // the gap before cleanup invokes git. A read-then-delete API would lose it.
    newerSha = await f.commit('new work after precheck\n');
    await f.git(['-C', f.checkout, 'push', 'origin', 'refs/heads/codex/active:refs/heads/codex/active']);
    return { data: { ref: 'refs/heads/codex/active', object: { type: 'commit', sha: f.sha } } };
  } } } };
  const warnings = [];
  assert.equal(await cleanupMergedBranch({ github, context: f.context, workspace: f.checkout,
    core: { info() {}, warning: (message) => warnings.push(message) },
  }), 'push-rejected');
  assert.equal((await f.remoteSha('codex/active')).stdout.trim(), newerSha);
  assert.equal(warnings.length, 1);
});

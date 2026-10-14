'use strict';

const { execFile: callbackExecFile } = require('node:child_process');
const { isAbsolute } = require('node:path');
const { promisify } = require('node:util');
const trustedExecFile = promisify(callbackExecFile);

// This code is loaded from the repository's default branch, never the PR head.
// Event fields are API data, not executable code or shell arguments.
async function cleanupMergedBranch({ github, context, core, execFile = trustedExecFile,
  workspace = process.env.GITHUB_WORKSPACE }) {
  const pr = context.payload.pull_request;
  const repository = context.payload.repository;
  const fullName = `${context.repo.owner}/${context.repo.repo}`;
  const branch = pr?.head?.ref;
  const reviewedSha = pr?.head?.sha;
  const skip = (reason) => {
    core.info(`Branch cleanup skipped: ${reason}.`);
    return reason;
  };

  if (pr?.merged !== true) return skip('not-merged');
  if (repository?.full_name !== fullName || pr?.base?.repo?.full_name !== fullName
      || pr?.head?.repo?.full_name !== fullName) return skip('different-repository');
  if (typeof branch !== 'string' || !branch.startsWith('codex/')) return skip('outside-development-prefix');
  if (typeof repository.default_branch !== 'string'
      || branch === repository.default_branch || branch === 'main') return skip('default-or-main-branch');
  // Restrict names to ordinary Git ref components. In particular exclude ref
  // metacharacters, dot components, .lock suffixes and option-like components.
  if (!branch.split('/').every((component) => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(component)
      && !component.includes('..') && !component.endsWith('.') && !component.endsWith('.lock'))) {
    return skip('invalid-development-ref');
  }
  if (typeof reviewedSha !== 'string' || !/^[a-f0-9]{40}$/i.test(reviewedSha)) return skip('missing-reviewed-sha');
  if (typeof workspace !== 'string' || !isAbsolute(workspace)) return skip('missing-trusted-checkout');

  const ref = `heads/${branch}`;
  let live;
  try {
    live = await github.rest.git.getRef({ ...context.repo, ref });
  } catch (error) {
    if (error.status === 404) return skip('already-deleted');
    core.warning(`Cannot inspect merged branch; retaining it (HTTP ${error.status ?? 'unknown'}).`);
    return 'lookup-failed';
  }

  // Ref lookup can return ambiguous or otherwise unexpected data; fail closed.
  if (live.data?.ref !== `refs/${ref}` || live.data?.object?.type !== 'commit') {
    core.warning('Unexpected branch reference response; retaining the branch.');
    return 'unexpected-ref';
  }
  if (live.data.object.sha !== reviewedSha) {
    core.warning('The branch contains work newer than the merged PR; retaining it.');
    return 'changed-sha';
  }

  try {
    // The API precheck alone is not sufficient: the ref may change after it.
    // Git's explicit lease checks the reviewed SHA at the remote deletion, so
    // any concurrent new commit rejects the push instead of deleting new work.
    // Checkout supplies origin and authentication; never rewrite its URL or
    // interpolate credentials/event data into a shell command.
    await execFile('git', [
      'push',
      `--force-with-lease=refs/${ref}:${reviewedSha}`,
      'origin',
      `:refs/${ref}`,
    ], { cwd: workspace, timeout: 30000, maxBuffer: 65536, encoding: 'utf8' });
    core.info(`Deleted merged development branch: ${branch}.`);
    return 'deleted';
  } catch {
    // Do not print subprocess output: remote diagnostics could contain auth
    // details. Do not retry without a lease or change protection rules.
    core.warning('Conditional branch deletion was not confirmed; its lease may have been rejected or deletion denied. No unconditional retry was attempted.');
    return 'push-rejected';
  }
}

module.exports = { cleanupMergedBranch };

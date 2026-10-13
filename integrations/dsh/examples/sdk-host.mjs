// Source-reviewed example only. Requires @deepseek-ai/dsh-sdk-client@0.2.1-alpha.2
// and a complete dedicated Profile with real host Domain/control services.
// Do not point this example at a target or candidate executable/library.
import { DeepSeekHarness } from '@deepseek-ai/dsh-sdk-client';

export async function launchAuthorizedBatch({ profile, patches, provider, model, rootSessionId, batchRef, env }) {
  // Explicit env replaces the child's entire environment. The host supplies approved
  // credentials privately, never in the batch prompt, work package or log.
  const harness = new DeepSeekHarness({ profile, patches, provider, model, env, maxTokens: 8192 });
  try {
    await harness.start();
    // Host must authorize this root Session and batch through its separate control channel.
    const session = harness.session(rootSessionId);
    await session.run(`Run the authorized frozen batch via run_recovery_batch. batch_ref=${JSON.stringify(batchRef)}`);
    // Read durable Domain receipts separately; finalResponse never proves a proposal/quality.
  } finally {
    // Real SDK close reaps the subprocess; tool resources still need host cleanup evidence.
    await harness.close();
  }
}

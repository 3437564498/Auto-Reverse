import { readFileSync } from 'node:fs';
import { Ajv } from 'ajv';
import { assertObjectJsonSchema, validateJsonSchemaValue, type JsonSchemaNode, type ObjectJsonSchema } from '@deepseek-ai/dsh-tools';
import type { AttemptBinding, Proposal } from './contracts.js';

const ajv = new Ajv({ allErrors: true, strict: true });
export const SHARED_PROPOSAL_SCHEMA = JSON.parse(readFileSync(new URL('../../../../schemas/proposal.schema.json', import.meta.url), 'utf8')) as Record<string, unknown>;
const fullProposal = ajv.compile(SHARED_PROPOSAL_SCHEMA);
const fullWork = ajv.compile(JSON.parse(readFileSync(new URL('../../../../schemas/work-package.schema.json', import.meta.url), 'utf8')));

/** Pinned DSH rejects minLength/minimum/minItems: keep these in final AJV validation. */
function project(source: Record<string, unknown>): JsonSchemaNode {
  const out: Record<string, unknown> = {};
  for (const key of ['type', 'additionalProperties', 'const', 'enum', 'description', 'title']) if (Object.hasOwn(source, key)) out[key] = source[key];
  if (source.properties !== undefined) {
    out.properties = Object.fromEntries(Object.entries(source.properties as Record<string, Record<string, unknown>>).map(([key, child]) => [key, project(child)]));
    // Model output must explicitly state all fields, even those Domain defaults.
    out.required = Object.keys(source.properties as object);
  }
  if (source.items !== undefined) out.items = project(source.items as Record<string, unknown>);
  return out as JsonSchemaNode;
}
export const PROPOSAL_SCHEMA = project(SHARED_PROPOSAL_SCHEMA) as ObjectJsonSchema;
assertObjectJsonSchema(PROPOSAL_SCHEMA);

export function validateWork(binding: AttemptBinding): void {
  if (!fullWork(binding.work)) throw new Error('INVALID_FROZEN_WORK_PACKAGE');
}

export function validateProposal(value: unknown, binding: AttemptBinding): Proposal {
  if (validateJsonSchemaValue(PROPOSAL_SCHEMA, value).length || !fullProposal(value)) throw new Error('INVALID_PROPOSAL_SCHEMA');
  const proposal = value as Proposal;
  for (const field of ['job_id', 'task_id', 'attempt_id', 'input_snapshot_id', 'contract_revision'] as const) {
    if (proposal[field] !== binding.work[field]) throw new Error('PROPOSAL_IDENTITY_MISMATCH');
  }
  if (!Number.isSafeInteger(proposal.contract_revision)) throw new Error('INVALID_CONTRACT_REVISION');
  if (proposal.artifact_refs.some(ref => !ref.startsWith(`${binding.work.candidate_namespace}/`))) throw new Error('ARTIFACT_SCOPE_MISMATCH');
  return structuredClone(proposal);
}

export function frozenPrompt(binding: AttemptBinding): string {
  // Serialize only the work contract, excluding lease, epoch and execution key.
  return JSON.stringify({ work_package: binding.work, output_contract: 'proposal/v1', instructions: binding.instructions ?? 'Investigate only this frozen work package. Submit PROPOSED output through structured_output; all independent quality decisions belong to the service.' });
}

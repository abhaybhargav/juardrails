import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Agent, InputGuardrailTripwireTriggered, run } from '@openai/agents';
import { inputGuardrail, outputGuardrail, toolInputGuardrail, toolOutputGuardrail, type Policy } from '../src/index.ts';

const folder = mkdtempSync(join(tmpdir(), 'juardrails-sdk-'));
const binary = join(folder, 'juardrails');
writeFileSync(binary, `#!/usr/bin/env node
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const args = process.argv.slice(2);
  if (JSON.stringify(args) !== JSON.stringify(['cli', '-namespace', 'finance', 'evaluate', 'expense-approval', '-'])) process.exit(2);
  if (!JSON.parse(input).state) process.exit(2);
  if (process.env.TEST_CLI_FAIL) { console.error('private credentials'); process.exit(1); }
  console.log(JSON.stringify({decision: process.env.TEST_DECISION || 'allow', policy_id: process.env.TEST_POLICY_ID || 'expense-approval', namespace: 'finance', id: 'evaluation-1'}));
});
`);
chmodSync(binary, 0o700);
const policy: Policy = { id: 'expense-approval', namespace: 'finance', binary };

test('input and output guardrails map Juardrails decisions to SDK tripwires', async () => {
  const guard = inputGuardrail(policy);
  assert.equal(guard.runInParallel, false);
  assert.equal((await guard.execute({ input: 'approve $20' } as never)).tripwireTriggered, false);
  process.env.TEST_DECISION = 'review';
  const review = await guard.execute({ input: 'approve $20' } as never);
  assert.equal(review.tripwireTriggered, true);
  assert.equal(review.outputInfo.decision, 'review');
  process.env.TEST_DECISION = 'block';
  assert.equal((await outputGuardrail(policy).execute({ agentOutput: 'approved' } as never)).tripwireTriggered, true);
  delete process.env.TEST_DECISION;
});

test('tool guardrails deny calls and fail closed on CLI errors', async () => {
  const guard = toolInputGuardrail(policy);
  const data = { toolCall: { name: 'approve', arguments: '{"amount":20}' } };
  assert.equal((await guard.run(data as never)).behavior.type, 'allow');
  process.env.TEST_DECISION = 'block';
  assert.equal((await guard.run(data as never)).behavior.type, 'throwException');
  assert.equal((await toolOutputGuardrail(policy).run({ ...data, output: 'approved' } as never)).behavior.type, 'throwException');
  delete process.env.TEST_DECISION;
  process.env.TEST_CLI_FAIL = '1';
  const error = await guard.run(data as never);
  assert.equal(error.behavior.type, 'throwException');
  assert.equal(error.outputInfo.decision, 'error');
  assert.equal(JSON.stringify(error).includes('private'), false);
  delete process.env.TEST_CLI_FAIL;
  process.env.TEST_POLICY_ID = 'wrong';
  assert.equal((await guard.run(data as never)).behavior.type, 'throwException');
  delete process.env.TEST_POLICY_ID;
});

test('real Agents SDK runner trips before the model', async () => {
  process.env.TEST_DECISION = 'block';
  const agent = new Agent({ name: 'Expense approver', inputGuardrails: [inputGuardrail(policy)] });
  await assert.rejects(() => run(agent, 'Approve a disallowed expense'), InputGuardrailTripwireTriggered);
  delete process.env.TEST_DECISION;
});

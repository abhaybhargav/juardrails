import { spawn } from 'node:child_process';
import type { AgentOutputType, InputGuardrail, OutputGuardrail, ToolInputGuardrailDefinition, ToolOutputGuardrailDefinition } from '@openai/agents';

export interface Policy {
  id: string;
  namespace?: string;
  binary?: string;
  timeoutMs?: number;
}

export interface DecisionInfo {
  decision: 'allow' | 'block' | 'review' | 'error';
  policy_id: string;
  namespace: string;
  evaluation_id?: string;
  policy_version?: number;
}

type StateBuilder<T> = (value: T) => unknown | Promise<unknown>;

function policyOptions(policy: Policy) {
  const { id, namespace = 'root', binary = 'juardrails', timeoutMs = 30000 } = policy;
  if (!id || !namespace || !binary || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('policy id, namespace, binary, and positive timeout are required');
  }
  return { id, namespace, binary, timeoutMs };
}

export async function evaluate(policy: Policy, state: unknown): Promise<Record<string, unknown>> {
  const options = policyOptions(policy);
  let payload: string;
  try {
    payload = JSON.stringify({ state });
    if (!payload) throw new Error('Invalid state');
  } catch {
    throw new Error('Juardrails state is not JSON serializable');
  }
  const stdout = await new Promise<string>((resolve, reject) => {
    const child = spawn(options.binary, ['cli', '-namespace', options.namespace, 'evaluate', options.id, '-'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(output);
    };
    const timer = setTimeout(() => { child.kill(); finish(new Error('Juardrails evaluation timed out')); }, options.timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      output += chunk;
      if (output.length > 2_000_000) { child.kill(); finish(new Error('Juardrails response too large')); }
    });
    // Do not copy stderr into SDK traces; it may contain deployment details.
    child.stderr.resume();
    child.on('error', () => finish(new Error('Juardrails CLI evaluation failed')));
    child.on('close', (code) => finish(code === 0 ? undefined : new Error('Juardrails CLI evaluation failed')));
    child.stdin.on('error', () => finish(new Error('Juardrails CLI input failed')));
    child.stdin.end(payload);
  });
  let result: unknown;
  try { result = JSON.parse(stdout); } catch { throw new Error('Juardrails returned invalid JSON'); }
  if (!result || typeof result !== 'object') throw new Error('Juardrails returned an invalid decision');
  const decision = result as Record<string, unknown>;
  if (!['allow', 'block', 'review', 'error'].includes(String(decision.decision)) ||
      decision.policy_id !== options.id || decision.namespace !== options.namespace) {
    throw new Error('Juardrails returned an invalid or mismatched decision');
  }
  return decision;
}

async function decide(policy: Policy, state: unknown): Promise<DecisionInfo> {
  const options = policyOptions(policy);
  try {
    const result = await evaluate(policy, state);
    return {
      decision: result.decision as DecisionInfo['decision'], policy_id: options.id, namespace: options.namespace,
      evaluation_id: typeof result.id === 'string' ? result.id : undefined,
      policy_version: typeof result.policy_version === 'number' ? result.policy_version : undefined,
    };
  } catch {
    return { decision: 'error', policy_id: options.id, namespace: options.namespace };
  }
}

export function inputGuardrail(policy: Policy, options: {
  state?: StateBuilder<unknown>; runInParallel?: boolean;
} = {}): InputGuardrail {
  const config = policyOptions(policy);
  return {
    name: `juardrails:${config.namespace}/${config.id}:input`,
    runInParallel: options.runInParallel ?? false,
    async execute({ input }) {
      let info: DecisionInfo;
      try { info = await decide(policy, options.state ? await options.state(input) : { input }); }
      catch { info = { decision: 'error', policy_id: config.id, namespace: config.namespace }; }
      return { outputInfo: info, tripwireTriggered: info.decision !== 'allow' };
    },
  };
}

export function outputGuardrail(policy: Policy, options: {
  state?: StateBuilder<unknown>;
} = {}): OutputGuardrail<AgentOutputType> {
  const config = policyOptions(policy);
  return {
    name: `juardrails:${config.namespace}/${config.id}:output`,
    async execute({ agentOutput }) {
      let info: DecisionInfo;
      try { info = await decide(policy, options.state ? await options.state(agentOutput) : { output: agentOutput }); }
      catch { info = { decision: 'error', policy_id: config.id, namespace: config.namespace }; }
      return { outputInfo: info, tripwireTriggered: info.decision !== 'allow' };
    },
  };
}

export function toolInputGuardrail(policy: Policy, options: {
  state?: StateBuilder<import('@openai/agents').ToolInputGuardrailData>;
} = {}): ToolInputGuardrailDefinition {
  const config = policyOptions(policy);
  return {
    type: 'tool_input', name: `juardrails:${config.namespace}/${config.id}:tool-input`,
    async run(data) {
      let info: DecisionInfo;
      try {
        const toolCall = data.toolCall;
        const state = options.state ? await options.state(data) : {
          tool_name: toolCall.name, tool_arguments: JSON.parse(toolCall.arguments || '{}'),
        };
        info = await decide(policy, state);
      } catch { info = { decision: 'error', policy_id: config.id, namespace: config.namespace }; }
      return { outputInfo: info, behavior: info.decision === 'allow' ? { type: 'allow' } : { type: 'throwException' } };
    },
  };
}

export function toolOutputGuardrail(policy: Policy, options: {
  state?: StateBuilder<import('@openai/agents').ToolOutputGuardrailData>;
} = {}): ToolOutputGuardrailDefinition {
  const config = policyOptions(policy);
  return {
    type: 'tool_output', name: `juardrails:${config.namespace}/${config.id}:tool-output`,
    async run(data) {
      let info: DecisionInfo;
      try { info = await decide(policy, options.state ? await options.state(data) : { tool_output: data.output }); }
      catch { info = { decision: 'error', policy_id: config.id, namespace: config.namespace }; }
      return { outputInfo: info, behavior: info.decision === 'allow' ? { type: 'allow' } : { type: 'throwException' } };
    },
  };
}

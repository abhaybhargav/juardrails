# Juardrails for OpenAI Agents SDK

The [Python](python/) and [TypeScript](typescript/) adapters return native OpenAI Agents SDK guardrail objects. They call `juardrails cli evaluate`, so authentication uses only the service-account credential in `~/.juardrails/credentials.json`. They never read or accept a human session token or API key. Install the single Juardrails executable and provision a service account with `policies:evaluate` on the policy namespace first.

Install these packages from this repository (neither package is published to a registry yet):

```sh
pip install ./integrations/openai-agents/python
npm install ./integrations/openai-agents/typescript
```

Python exports `Policy`, `input_guardrail`, `output_guardrail`, `tool_input_guardrail_for`, and `tool_output_guardrail_for`. TypeScript exports `inputGuardrail`, `outputGuardrail`, `toolInputGuardrail`, and `toolOutputGuardrail`. Each factory accepts a policy ID and optional namespace, binary path, timeout, and custom state builder.

Input guardrails run before the model by default (`run_in_parallel=False` in Python, `runInParallel: false` in TypeScript). Only an explicit `allow` decision passes. `block`, `review`, `error`, malformed responses, mismatched policy IDs, timeouts, CLI failures, and state serialization failures trigger the SDK tripwire. The structured `output_info` / `outputInfo` contains decision metadata without the state or CLI stderr. Tool guardrails use the SDK's exception behavior on denials.

See the [full guide](https://abhaybhargav.github.io/juardrails/openai-agents.html) for working agent examples and the SDK enforcement boundaries.

## Test

```sh
uv venv --python 3.12 /tmp/juardrails-agents-venv
uv pip install --python /tmp/juardrails-agents-venv/bin/python -e ./integrations/openai-agents/python pytest
/tmp/juardrails-agents-venv/bin/pytest integrations/openai-agents/python/tests -q
npm ci --prefix integrations/openai-agents/typescript
npm test --prefix integrations/openai-agents/typescript
```

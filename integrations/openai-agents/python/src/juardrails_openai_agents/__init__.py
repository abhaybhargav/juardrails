"""OpenAI Agents SDK guardrails backed by the authenticated Juardrails CLI."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Callable

from agents import GuardrailFunctionOutput, InputGuardrail, OutputGuardrail, ToolGuardrailFunctionOutput
from agents.decorators import tool_input_guardrail, tool_output_guardrail


StateBuilder = Callable[[Any], Any]


@dataclass(frozen=True)
class Policy:
    id: str
    namespace: str = "root"
    binary: str = "juardrails"
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.id or not self.namespace or not self.binary or self.timeout <= 0:
            raise ValueError("policy id, namespace, binary, and positive timeout are required")


async def evaluate(policy: Policy, state: Any) -> dict[str, Any]:
    """Run a live evaluation using ~/.juardrails/credentials.json via the CLI."""
    try:
        payload = json.dumps({"state": state}, allow_nan=False).encode()
        process = await asyncio.create_subprocess_exec(
            policy.binary, "cli", "-namespace", policy.namespace, "evaluate", policy.id, "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(payload), timeout=policy.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            raise RuntimeError("Juardrails evaluation timed out") from None
        if process.returncode != 0:
            raise RuntimeError("Juardrails CLI evaluation failed")
        result = json.loads(stdout)
        if not isinstance(result, dict) or result.get("decision") not in {"allow", "block", "review", "error"}:
            raise RuntimeError("Juardrails returned an invalid decision")
        if result.get("policy_id") != policy.id or result.get("namespace") != policy.namespace:
            raise RuntimeError("Juardrails returned a decision for a different policy")
        return result
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Juardrails evaluation could not be completed") from exc


async def _decision(policy: Policy, state: Any) -> dict[str, Any]:
    try:
        result = await evaluate(policy, state)
        return {
            "decision": result["decision"],
            "policy_id": result["policy_id"],
            "namespace": result["namespace"],
            "evaluation_id": result.get("id"),
            "policy_version": result.get("policy_version"),
        }
    except Exception:
        # Deliberately omit CLI stderr and state from SDK traces and exception messages.
        return {"decision": "error", "policy_id": policy.id, "namespace": policy.namespace}


def input_guardrail(policy: Policy, *, state_builder: StateBuilder | None = None, run_in_parallel: bool = False) -> InputGuardrail:
    async def check(ctx: Any, agent: Any, input: Any) -> GuardrailFunctionOutput:
        try:
            state = state_builder(input) if state_builder else {"input": input}
            info = await _decision(policy, state)
        except Exception:
            info = {"decision": "error", "policy_id": policy.id, "namespace": policy.namespace}
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=info["decision"] != "allow")

    return InputGuardrail(guardrail_function=check, name=f"juardrails:{policy.namespace}/{policy.id}:input", run_in_parallel=run_in_parallel)


def output_guardrail(policy: Policy, *, state_builder: StateBuilder | None = None) -> OutputGuardrail:
    async def check(ctx: Any, agent: Any, output: Any) -> GuardrailFunctionOutput:
        try:
            state = state_builder(output) if state_builder else {"output": output}
            info = await _decision(policy, state)
        except Exception:
            info = {"decision": "error", "policy_id": policy.id, "namespace": policy.namespace}
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=info["decision"] != "allow")

    return OutputGuardrail(guardrail_function=check, name=f"juardrails:{policy.namespace}/{policy.id}:output")


def tool_input_guardrail_for(policy: Policy, *, state_builder: StateBuilder | None = None):
    @tool_input_guardrail(name=f"juardrails:{policy.namespace}/{policy.id}:tool-input")
    async def check(data: Any) -> ToolGuardrailFunctionOutput:
        try:
            context = data.context
            state = state_builder(context) if state_builder else {
                "tool_name": context.tool_name,
                "tool_arguments": json.loads(context.tool_arguments or "{}"),
            }
            info = await _decision(policy, state)
        except Exception:
            info = {"decision": "error", "policy_id": policy.id, "namespace": policy.namespace}
        return (ToolGuardrailFunctionOutput.allow(info) if info["decision"] == "allow"
                else ToolGuardrailFunctionOutput.raise_exception(info))

    return check


def tool_output_guardrail_for(policy: Policy, *, state_builder: StateBuilder | None = None):
    @tool_output_guardrail(name=f"juardrails:{policy.namespace}/{policy.id}:tool-output")
    async def check(data: Any) -> ToolGuardrailFunctionOutput:
        try:
            state = state_builder(data) if state_builder else {"tool_output": data.output}
            info = await _decision(policy, state)
        except Exception:
            info = {"decision": "error", "policy_id": policy.id, "namespace": policy.namespace}
        return (ToolGuardrailFunctionOutput.allow(info) if info["decision"] == "allow"
                else ToolGuardrailFunctionOutput.raise_exception(info))

    return check

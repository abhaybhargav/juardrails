import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from agents import Agent, InputGuardrailTripwireTriggered, Runner
import pytest

from juardrails_openai_agents import (
    Policy, evaluate, input_guardrail, output_guardrail,
    tool_input_guardrail_for, tool_output_guardrail_for,
)


def fake_cli(tmp_path: Path) -> str:
    path = tmp_path / "juardrails"
    path.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
assert args[:3] == ['cli', '-namespace', 'finance']
assert args[3:] == ['evaluate', 'expense-approval', '-']
body = json.load(sys.stdin)
assert 'state' in body
if os.getenv('TEST_CLI_FAIL'):
    print('private credentials', file=sys.stderr)
    sys.exit(1)
print(json.dumps({'decision': os.getenv('TEST_DECISION', 'allow'), 'policy_id': os.getenv('TEST_POLICY_ID', 'expense-approval'), 'namespace': 'finance', 'id': 'evaluation-1'}))
""")
    path.chmod(0o700)
    return str(path)


def test_agent_guardrails(tmp_path, monkeypatch):
    policy = Policy("expense-approval", "finance", fake_cli(tmp_path))
    guard = input_guardrail(policy)
    assert guard.run_in_parallel is False
    assert asyncio.run(guard.guardrail_function(None, None, "Approve $20")).tripwire_triggered is False
    monkeypatch.setenv("TEST_DECISION", "review")
    result = asyncio.run(guard.guardrail_function(None, None, "Approve $20"))
    assert result.tripwire_triggered is True
    assert result.output_info["decision"] == "review"
    monkeypatch.setenv("TEST_DECISION", "block")
    assert asyncio.run(output_guardrail(policy).guardrail_function(None, None, "approved")).tripwire_triggered
    monkeypatch.setenv("TEST_CLI_FAIL", "1")
    result = asyncio.run(guard.guardrail_function(None, None, "private request"))
    assert result.output_info["decision"] == "error"
    assert "private" not in json.dumps(result.output_info)


def test_tool_guardrails_and_policy_match(tmp_path, monkeypatch):
    policy = Policy("expense-approval", "finance", fake_cli(tmp_path))
    data = SimpleNamespace(context=SimpleNamespace(tool_name="approve", tool_arguments='{"amount":20}'))
    guard = tool_input_guardrail_for(policy)
    assert asyncio.run(guard.guardrail_function(data)).behavior["type"] == "allow"
    monkeypatch.setenv("TEST_DECISION", "block")
    assert asyncio.run(guard.guardrail_function(data)).behavior["type"] == "raise_exception"
    output_data = SimpleNamespace(output={"status": "approved"})
    assert asyncio.run(tool_output_guardrail_for(policy).guardrail_function(output_data)).behavior["type"] == "raise_exception"
    monkeypatch.setenv("TEST_DECISION", "allow")
    monkeypatch.setenv("TEST_POLICY_ID", "other-policy")
    assert asyncio.run(guard.guardrail_function(data)).behavior["type"] == "raise_exception"


def test_missing_binary_fails_closed():
    policy = Policy("expense-approval", "finance", "/definitely/missing/juardrails")
    result = asyncio.run(input_guardrail(policy).guardrail_function(None, None, "hi"))
    assert result.tripwire_triggered
    assert result.output_info["decision"] == "error"


def test_real_agents_runner_stops_before_model(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_DECISION", "block")
    policy = Policy("expense-approval", "finance", fake_cli(tmp_path))
    agent = Agent(name="Expense approver", input_guardrails=[input_guardrail(policy)])
    with pytest.raises(InputGuardrailTripwireTriggered):
        asyncio.run(Runner.run(agent, "Approve a disallowed expense"))

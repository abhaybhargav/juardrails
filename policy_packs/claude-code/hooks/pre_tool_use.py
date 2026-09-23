#!/usr/bin/env python3
"""Claude Code PreToolUse adapter. Only a Juardrails allow decision permits a call."""
import json
import os
import re
import subprocess
import sys

POLICY_ID = "claude-code-tool-use"
MAX_INPUT = 256 * 1024
TOOLS = {"Bash", "PowerShell", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch"}
SENSITIVE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b|"
    r"(?:^|[/\s@'\"])\.env(?:$|[/\s'\"])|"
    r"\.ssh/|\.aws/|\.juardrails/|credentials\.json|id_rsa",
    re.IGNORECASE,
)


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "Juardrails: " + reason,
    }}))
    return 0


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        return deny("tool input exceeds the inspection limit")
    try:
        event = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return deny("invalid Claude Code hook input")
    name = event.get("tool_name") if isinstance(event, dict) else None
    if not isinstance(name, str) or not (name in TOOLS or name.startswith("mcp__")) or not isinstance(event.get("tool_input"), dict):
        return deny("unsupported tool input")
    if SENSITIVE.search(json.dumps(event["tool_input"])):
        return deny("tool input references obvious credential material")
    state = {"state": {
        "source": "claude-code", "tool_name": event["tool_name"],
        "tool_input": event["tool_input"],
        "project_dir": os.environ.get("CLAUDE_PROJECT_DIR", ""),
    }}
    executable = os.environ.get("JUARD_BIN", "juard")
    prefix = [executable, "cli"] if os.path.basename(executable).lower() in ("juardrails", "juardrails.exe") else [executable]
    try:
        proc = subprocess.run(
            prefix + ["evaluate", POLICY_ID, "-"],
            input=json.dumps(state).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=45, check=False,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return deny("policy evaluation unavailable")
    if proc.returncode != 0:
        return deny("policy evaluation failed; check server, service credential, and provider")
    try:
        decision = json.loads(proc.stdout).get("decision")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return deny("invalid policy response")
    if decision != "allow":
        return deny("policy decision: " + str(decision))
    return 0  # no decision: normal Claude permission rules still apply


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(deny("internal hook failure"))

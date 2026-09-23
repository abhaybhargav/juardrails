import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACK = Path(__file__).resolve().parents[1]
HOOK = PACK / "hooks" / "pre_tool_use.py"

spec = importlib.util.spec_from_file_location("installer", PACK / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class PackTest(unittest.TestCase):
    def hook(self, response, event=None, exit_code=0):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "juard"
            fake.write_text("#!/usr/bin/env python3\nimport sys\n"
                            "body = sys.stdin.read()\n"
                            "assert 'tool_name' in body\n"
                            f"print({response!r})\n"
                            f"sys.exit({exit_code})\n")
            fake.chmod(0o700)
            env = dict(os.environ, JUARD_BIN=str(fake))
            event = event or {"tool_name": "Bash", "tool_input": {"command": "go test ./..."}}
            proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event).encode(),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=True)
            return proc.stdout.decode()

    def test_only_allow_passes(self):
        self.assertEqual(self.hook('{"decision":"allow"}'), "")
        for decision in ("block", "review", "error"):
            output = json.loads(self.hook(json.dumps({"decision": decision})))
            self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_service_failure_denies(self):
        output = json.loads(self.hook('{}', exit_code=1))
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        output = json.loads(self.hook('bad JSON'))
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_mcp_tool_is_screened(self):
        event = {"tool_name": "mcp__github__create_issue", "tool_input": {"title": "test"}}
        output = json.loads(self.hook('{"decision":"block"}', event=event))
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_obvious_credential_reference_is_denied_locally(self):
        event = {"tool_name": "Bash", "tool_input": {"command": "cat .env"}}
        proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event).encode(),
                              stdout=subprocess.PIPE, check=True, env=dict(os.environ, JUARD_BIN="/missing/juard"))
        decision = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn("credential material", decision["permissionDecisionReason"])

    def test_installer_preserves_existing_settings_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            claude = project / ".claude"
            claude.mkdir()
            settings = claude / "settings.json"
            settings.write_text(json.dumps({"permissions": {"deny": ["Bash(rm *)"]}}))
            installer.install(project, apply=False, force=False, juard="juard")
            installer.install(project, apply=False, force=False, juard="juard")
            data = json.loads(settings.read_text())
            self.assertEqual(data["permissions"]["deny"], ["Bash(rm *)"])
            self.assertEqual(len(data["hooks"]["PreToolUse"]), 1)
            self.assertTrue((claude / "skills" / "juardrails" / "SKILL.md").exists())
            self.assertTrue((claude / "skills" / "claude-code-guardrails" / "SKILL.md").exists())
            installer.install(project, apply=False, force=False, juard="juard", namespace="team/dev")
            command = json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            self.assertIn("JUARDRAILS_NAMESPACE=team/dev", command)
            with self.assertRaises(ValueError):
                installer.install(project, apply=False, force=False, juard="juard", namespace="../bad")


if __name__ == "__main__":
    unittest.main()

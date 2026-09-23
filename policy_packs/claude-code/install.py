#!/usr/bin/env python3
"""Install the Claude Code pack into one project without changing global settings."""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

PACK = Path(__file__).resolve().parent
HOOK_COMMAND = 'python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/juardrails_pre_tool_use.py"'
MATCHER = 'Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|mcp__.*'


def install(project: Path, apply: bool, force: bool, juard: str, namespace: str = "root") -> None:
    project = project.resolve()
    if not project.is_dir():
        raise ValueError(f"project directory does not exist: {project}")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}(?:/[a-z][a-z0-9_-]{0,63})*", namespace):
        raise ValueError("invalid namespace")
    claude = project / ".claude"
    settings_path = claude / "settings.json"
    if claude.is_symlink() or settings_path.is_symlink():
        raise ValueError("Claude configuration path cannot be a symlink")
    settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    if not isinstance(settings, dict):
        raise ValueError("Claude settings must be a JSON object")
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse", []), list):
        raise ValueError("existing hook settings have an unexpected structure")
    existing = hooks.setdefault("PreToolUse", [])
    command = HOOK_COMMAND
    if namespace != "root":
        command = "JUARDRAILS_NAMESPACE=" + shlex.quote(namespace) + " " + command
    if juard != "juard":
        binary = Path(juard).resolve()
        if not binary.is_file():
            raise FileNotFoundError(binary)
        command = "JUARD_BIN=" + shlex.quote(str(binary)) + " " + command
    hook = {"matcher": MATCHER, "hooks": [{"type": "command", "command": command, "timeout": 60}]}
    installed = False
    for item in existing:
        if not isinstance(item, dict) or not isinstance(item.get("hooks"), list):
            continue
        for handler in item["hooks"]:
            if isinstance(handler, dict) and "juardrails_pre_tool_use.py" in handler.get("command", ""):
                item["matcher"] = MATCHER
                handler.update(hook["hooks"][0])
                installed = True
    if not installed:
        existing.append(hook)
    copies = [(PACK / "hooks" / "pre_tool_use.py", claude / "hooks" / "juardrails_pre_tool_use.py")]
    for name in ("juardrails", "claude-code-guardrails"):
        copies.append((PACK / "skills" / name / "SKILL.md", claude / "skills" / name / "SKILL.md"))
    for src, dst in copies:
        if dst.parent.is_symlink() or dst.is_symlink():
            raise ValueError(f"pack destination cannot be a symlink: {dst}")
        if dst.exists() and dst.read_bytes() != src.read_bytes() and not force:
            raise FileExistsError(f"existing file differs: {dst}; use --force to replace")
    if apply:
        prefix = [juard, "cli"] if Path(juard).name.lower() in ("juardrails", "juardrails.exe") else [juard]
        subprocess.run(prefix + ["-namespace", namespace, "apply", str(PACK / "policies" / "claude-code-tool-use.yaml")], check=True)
    for src, dst in copies:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    claude.mkdir(parents=True, exist_ok=True)
    tmp = settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(tmp, settings_path)
    print(f"Installed Claude Code pack in {project}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path, help="Claude Code project directory")
    parser.add_argument("--no-apply", action="store_true", help="install files without applying the Juardrails policy")
    parser.add_argument("--force", action="store_true", help="replace differing pack files")
    parser.add_argument("--juard", default="juard", help="Juardrails CLI executable")
    parser.add_argument("--namespace", default="root", help="policy namespace (default: root)")
    args = parser.parse_args()
    install(args.project, not args.no_apply, args.force, args.juard, args.namespace)


if __name__ == "__main__":
    main()

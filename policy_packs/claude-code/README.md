# Claude Code policy pack

This pack screens proposed tool calls with the active `claude-code-tool-use` policy before Claude Code executes them. Its three criteria assess destructive changes, secret exposure, and unsafe external actions. A project-level `PreToolUse` hook invokes `juard evaluate`; only `decision: "allow"` passes through to Claude Code's normal permission checks. The pack includes two skills: `juardrails` for policy operations and `claude-code-guardrails` for working with this integration.

## Install in one Claude Code project

1. Start Juardrails with a configured Jev provider. Provision a service credential at `~/.juardrails/credentials.json` with `policies:create`, `policies:update`, `policies:read`, and `policies:evaluate` for the target namespace. The CLI uses that file; no human session token is accepted.
2. Build the CLI with `make build` from this repository.
3. Install the pack from this repository:

   ```sh
   python3 policy_packs/claude-code/install.py /path/to/claude-project --juard "$PWD/bin/juard"
   ```

The installer applies the YAML policy to `root`, copies the hook and skills into `/path/to/claude-project/.claude/`, and merges a `PreToolUse` entry into `.claude/settings.json`. Use `--namespace NAME` for another namespace. It preserves existing settings and refuses to replace differing pack files unless `--force` is set. Use `--no-apply` to install files while the server is unavailable, then run `juard apply policy_packs/claude-code/policies/claude-code-tool-use.yaml` later. Reapplying an existing policy creates a new revision. The CLI must remain at the `--juard` path for the installed hook. Add it to `PATH` for Claude to use the skill's `juard` commands.

To put the general skill in another harness, copy `skills/juardrails/` to that harness's skill directory. For Codex, use `~/.codex/skills/juardrails/`; for Claude Code, the installer places it in `.claude/skills/juardrails/`. The skill teaches policy work. Enforcement requires a harness hook or equivalent tool interception.

## Coverage and limits

The hook matches Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, WebFetch, WebSearch, and MCP tool calls. It denies oversized input, malformed responses, non-allow decisions, and service errors. It locally rejects obvious credential references before contacting Jev. Other tool types, direct shell commands outside Claude Code, and direct API calls are outside this hook's coverage. A user who can edit or disable project hooks can bypass it; use managed settings and operating-system controls where stronger enforcement is required. Claude Code may also proceed if its hook process is killed or times out, so treat this pack as a defense layer, not a complete sandbox.

Live evaluation sends the proposed tool input to the configured Jev provider. The local credential check catches common secret names and token patterns but cannot detect every secret. Use this pack only where that provider may receive the inspected project data. Evaluation adds a provider request to each matched call and may affect latency and cost.

## Check the pack

```sh
juard explain claude-code-tool-use
python3 -m unittest discover -s policy_packs/claude-code/tests -v
go test ./...
```

A safe `go test ./...` call should be allowed; a recursive deletion or command that posts `.env` to a remote URL should be blocked. Inspect the live trace with `juard history claude-code-tool-use`. The YAML policy is a starting point: test it against your own workflows and tune thresholds before broad rollout.

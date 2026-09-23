---
name: claude-code-guardrails
description: Inspect or operate the Juardrails Claude Code tool-use policy pack, its PreToolUse hook, and its policy decisions. Use when asked to secure Claude Code tool calls with Juardrails.
---

# Claude Code guardrails

The project hook screens Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, WebFetch, WebSearch, and MCP tool calls through the active `claude-code-tool-use` policy. The hook denies a tool call unless live Juardrails evaluation returns `allow`; the normal Claude Code permission rules still apply afterward. Do not disable the hook or change its policy to get past a denial. Explain the decision and ask the user to adjust the policy or proposed action if appropriate.

Use `juardrails cli explain claude-code-tool-use` to inspect its criteria and `juardrails cli history claude-code-tool-use` to inspect recent results. Use `juardrails cli get claude-code-tool-use` for the full YAML. Add `-namespace NAME` before the command when the pack was installed outside `root`. For authoring or evaluating other policies, use the `juardrails` skill.

The default cutoffs are 0.20 for destructive changes, 0.40 for secret exposure, and 0.20 for unsafe external actions. Routine directory listings should pass; publishing sensitive content should not. The scores are model judgments, so inspect traces when a call is unexpectedly denied or allowed.

The hook requires a reachable Juardrails server, a service credential at `~/.juardrails/credentials.json`, an active policy, and a configured Jev provider. If any is unavailable, calls matched by the hook are denied. Live evaluation sends the proposed tool input to the configured provider; discuss that data flow before applying the pack to sensitive workspaces.

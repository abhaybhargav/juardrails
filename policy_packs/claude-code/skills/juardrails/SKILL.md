---
name: juardrails
description: Use Juardrails to discover, explain, author, validate, and evaluate guardrail policies in an authorized namespace. Use when a task asks for policy work or a policy decision.
---

# Juardrails

Use the installed `juardrails cli` command. It reads a service-account credential from `~/.juardrails/credentials.json`; do not read, print, copy, or pass that token yourself. If the CLI is unavailable or authorization fails, report the failure instead of bypassing it.

- Discover access with `juardrails cli admin namespaces list` only when admin access is available, or `juardrails cli list` in the selected namespace. Select another namespace with `juardrails cli -namespace NAME ...`.
- Inspect a policy with `juardrails cli explain ID` or `juardrails cli get ID` before proposing a change.
- Author a YAML policy, run `juardrails cli validate FILE`, and use `juardrails cli apply FILE` only when the user has requested the write. The server enforces the service account's grants.
- Use `juardrails cli evaluate ID FILE` for live evaluation of an active policy; `FILE` contains JSON `{"state": ...}`. Use `juardrails cli simulate ID FILE` only for supplied-answer tests; simulations do not call the model provider.
- Interpret only `decision: "allow"` as allow. `block`, `review`, `error`, API failures, and transport failures do not authorize an action. Inspect the JSON `results` and `error` fields to explain a decision.

Policy state may be sent to the configured Jev provider during live evaluation. Do not put credentials or private data in state unless the deployment explicitly permits that transfer.

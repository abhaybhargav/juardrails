---
name: juardrails-expense-demo-expense-approval
description: "This policy evaluates expenses against a $500 delegated limit, verifies receipt and purpose documentation, checks allowed categories, and detects attempts to override approval rules."
---

# Juardrails policy expense-demo/expense-approval

Use this policy when assessing whether a proposed expense meets delegation limits, documentation requirements, category permissions, and is free from override instructions.

This skill was generated from Juardrails policy `expense-demo/expense-approval` revision 1. The bundled [policy snapshot](references/policy.yaml) is for orientation; fetch the current definition before acting.

1. Run `juardrails cli -namespace expense-demo explain expense-approval` to inspect the current policy. If it has changed materially since this skill was generated, confirm this skill still fits the task.
2. Put the state to check in a local JSON file as `{"state": ...}`. Include only data the deployment permits sending to its configured Jev provider.
3. Run `juardrails cli -namespace expense-demo evaluate expense-approval STATE_FILE` and inspect the JSON decision and criterion results.
4. Proceed only if `decision` is exactly `allow`. Treat `block`, `review`, `error`, a missing decision, or any CLI failure as no authorization to proceed.

The CLI reads its service-account credential from `~/.juardrails/credentials.json`. Never read, print, copy, or include that token in a prompt. If the CLI is unavailable or access is denied, ask for an authorized service credential; do not bypass Juardrails.

# Expense approval agent case study

This example uses a generated Juardrails skill in a small OpenAI Chat Completions agent. The agent proposes an expense action through a tool call. The harness submits the original fictional expense record to `juardrails cli evaluate` and permits a simulated approval only when the agent proposes approval **and** the saved policy returns `allow`. It has no connection to an expense or payment system.

The source files are:

- `policy.json`: active four-criterion expense policy in `expense-demo`.
- `skill/`: the installable skill generated from that policy using a real OpenAI API call on 27 September 2026.
- `agent.py`: OpenAI tool-calling agent and mandatory Juardrails CLI gate.
- `scenarios.json`: six fictional live cases.
- `simulation-cases.json` and `simulate.py`: supplied-answer allow, block, review, and error cases.
- `observed-results.json`: sanitized results from the recorded run, without credentials or raw provider responses.
- `run_study.py`: isolated end-to-end reproducer.

## Reproduce

From the repository root, put `OPENAI_API_KEY` and `TYPESAFE_API_KEY` in `.env` or the process environment. Install Go and Python 3, then run:

```sh
python3 examples/expense-approval/run_study.py --artifacts-dir /tmp/expense-study-output
```

The runner builds the current Juardrails binary, creates a temporary database and local server, bootstraps an admin, creates the expense policy, and injects a short-lived service credential with only `policies:read`, `policies:evaluate`, and `policies:simulate` on `expense-demo`. It generates a fresh skill with OpenAI, runs the six live agent cases against TypeSafe Jev, and runs the four supplied-answer simulations. The temporary credentials and database are removed on exit. The artifact directory keeps the generated ZIP and raw observations; choose a new path for each run.

Run the local harness tests without either provider:

```sh
python3 -m unittest discover -s examples/expense-approval -p 'test_*.py'
```

The [case study](https://abhaybhargav.github.io/juardrails/expense-agent-case-study.html) explains the observed behavior, timing limits, and enforcement boundary. Provider responses may change on a later run. A production finance integration needs authoritative checks for amounts and receipt records before any irreversible action.

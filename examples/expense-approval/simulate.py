#!/usr/bin/env python3
"""Exercise the generated skill's Juardrails policy with supplied typed answers."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from agent import load_skill, permitted_action


ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True)
    parser.add_argument("--binary", default=os.environ.get("JUARDRAILS_BIN", "juardrails"))
    parser.add_argument("--cases", default=str(ROOT / "simulation-cases.json"))
    args = parser.parse_args()
    namespace, policy_id, _, _ = load_skill(args.skill)
    cases = json.loads(Path(args.cases).read_text())
    matched = 0
    for case in cases:
        fd, path = tempfile.mkstemp(prefix="juardrails-expense-sim-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as file:
                json.dump({"state": {"expense": {"case": case["id"]}}, "answers": case["answers"]}, file)
            response = subprocess.run(
                [args.binary, "cli", "-namespace", namespace, "simulate", policy_id, path],
                capture_output=True, text=True, timeout=15,
            )
            if response.returncode:
                try:
                    decision = json.loads(response.stderr.split("HTTP 422: ", 1)[1])["decision"]
                except (IndexError, ValueError, KeyError):
                    decision = "error"
            else:
                decision = json.loads(response.stdout)["decision"]
            action = permitted_action({"action": "approve"}, {"decision": decision})
            matched += decision == case["expected"]
            print(f"{case['id']}: expected={case['expected']} observed={decision} action={action}")
        finally:
            Path(path).unlink(missing_ok=True)
    print(f"Matched expected decisions: {matched}/{len(cases)}")
    if matched != len(cases):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise the installed webhook with real Kubernetes server-side dry runs."""

import argparse
import copy
import json
import subprocess
import time

NAMESPACE = "juardrails-smoke"
BASE = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "admission-safe", "namespace": NAMESPACE},
    "spec": {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "restartPolicy": "Never",
        "containers": [{
            "name": "app", "image": "busybox:1.36", "command": ["sh", "-c", "sleep 30"],
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        }],
    },
}


def cases():
    yield "safe-versioned-nonroot", BASE, True
    variants = {
        "privileged-container": lambda p: p["spec"]["containers"][0]["securityContext"].update(privileged=True, allowPrivilegeEscalation=True),
        "hostpath-root-mount": lambda p: p["spec"].update(volumes=[{"name": "host", "hostPath": {"path": "/"}}]),
        "host-network": lambda p: p["spec"].update(hostNetwork=True),
        "root-user": lambda p: p["spec"]["containers"][0]["securityContext"].update(runAsUser=0),
        "floating-image": lambda p: p["spec"]["containers"][0].update(image="busybox:latest"),
        "token-automount": lambda p: p["spec"].update(automountServiceAccountToken=True),
    }
    for name, change in variants.items():
        p = copy.deepcopy(BASE)
        p["metadata"]["name"] = name
        change(p)
        yield name, p, False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output", help="write sanitized JSON observations")
    args = parser.parse_args()
    kube = ["kubectl", "--context", args.context]
    subprocess.run(kube + ["create", "namespace", NAMESPACE], capture_output=True, check=False)
    subprocess.run(kube + ["label", "namespace", NAMESPACE, "juardrails.io/admission=enabled", "--overwrite"], check=True, capture_output=True)
    observations = []
    for name, pod, expected_allow in cases():
        started = time.monotonic()
        result = subprocess.run(kube + ["create", "-f", "-", "--dry-run=server", "-o", "name"],
                                input=json.dumps(pod), capture_output=True, text=True, timeout=50)
        allowed = result.returncode == 0
        message = (result.stderr or result.stdout).strip()
        webhook_denied = 'pod-security.juardrails.io' in message
        matched = allowed == expected_allow and (allowed or webhook_denied)
        row = {"case": name, "expected": "allow" if expected_allow else "deny", "observed": "allow" if allowed else "deny",
               "webhook_denied": webhook_denied, "matched": matched, "elapsed_ms": round((time.monotonic() - started) * 1000), "message": message[-500:]}
        observations.append(row)
        print(f"{name:25s} expected={row['expected']:5s} observed={row['observed']:5s} match={matched}")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(observations, f, indent=2)
    if not all(row["matched"] for row in observations):
        raise SystemExit("smoke test failed; inspect observed messages")
    print(f"{len(observations)}/{len(observations)} admission decisions matched")


if __name__ == "__main__":
    main()

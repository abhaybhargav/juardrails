#!/usr/bin/env python3
"""Probe a live Juardrails webhook using Kubernetes Goat's system-monitor Pod template."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import time

GOAT_COMMIT = "723a0db478f050d173d23b4ce5044b65bce0bdd0"
WEBHOOK = 'admission webhook "pod-security.juardrails.io" denied'


def run(argv, *, input_data=None, check=True):
    result = subprocess.run(argv, input=input_data, text=True, capture_output=True, check=False, timeout=60)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(str(a) for a in argv[:5])} failed: {result.stderr.strip()[-500:]}")
    return result


def decode_stream(data):
    decoder = json.JSONDecoder()
    objects = []
    while data.strip():
        obj, end = decoder.raw_decode(data.lstrip())
        objects.append(obj)
        data = data.lstrip()[end:]
    return objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="explicit kubectl context")
    parser.add_argument("--goat-dir", type=Path, required=True, help="Kubernetes Goat checkout at the pinned commit")
    parser.add_argument("--namespace", default="goat-guarded")
    parser.add_argument("--output", type=Path, help="write sanitized JSON observations")
    args = parser.parse_args()
    goat = args.goat_dir.resolve()
    sha = run(["git", "-C", str(goat), "rev-parse", "HEAD"]).stdout.strip()
    if sha != GOAT_COMMIT:
        parser.error(f"Kubernetes Goat checkout must be at {GOAT_COMMIT}; found {sha}")
    manifest = goat / "scenarios/system-monitor/deployment.yaml"
    kube = ["kubectl", "--context", args.context]
    raw = run(kube + ["create", "--dry-run=client", "--validate=false", "-f", str(manifest), "-o", "json"]).stdout
    deployment = next((o for o in decode_stream(raw) if o.get("kind") == "Deployment" and o["metadata"]["name"] == "system-monitor-deployment"), None)
    if deployment is None:
        raise RuntimeError("system-monitor Deployment not found in pinned Kubernetes Goat manifest")
    spec = deployment["spec"]["template"]["spec"]
    if not (spec.get("hostPID") and spec.get("hostIPC") and any(v.get("hostPath") for v in spec.get("volumes", []))
            and any(c.get("securityContext", {}).get("privileged") for c in spec.get("containers", []))):
        raise RuntimeError("upstream system-monitor template no longer has the expected unsafe settings")
    run(kube + ["create", "namespace", args.namespace], check=False)
    run(kube + ["label", "namespace", args.namespace, "juardrails.io/admission=enabled", "--overwrite"])
    suffix = str(int(time.time()))
    name = "goat-system-monitor-" + suffix
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": args.namespace}, "spec": spec}
    dry = run(kube + ["create", "--dry-run=server", "-f", "-"], input_data=json.dumps(pod), check=False)
    dry_message = dry.stderr.strip()
    if dry.returncode == 0 or WEBHOOK not in dry_message:
        raise RuntimeError(f"Goat Pod was not denied by the Juardrails webhook: {dry_message[-500:]}")
    print("Goat Pod dry-run: denied by Juardrails webhook")

    controller = copy.deepcopy(deployment)
    controller["metadata"] = {"name": name, "namespace": args.namespace}
    controller["spec"]["template"]["metadata"]["labels"] = controller["spec"]["selector"]["matchLabels"]
    created = False
    event_message = ""
    try:
        run(kube + ["create", "-f", "-"], input_data=json.dumps(controller))
        created = True
        for _ in range(40):
            events = json.loads(run(kube + ["get", "events", "-n", args.namespace, "-o", "json"]).stdout)["items"]
            for event in events:
                message = event.get("message", "")
                if event.get("reason") == "FailedCreate" and name in event.get("involvedObject", {}).get("name", "") and WEBHOOK in message:
                    event_message = message
                    break
            if event_message:
                break
            time.sleep(1)
        if not event_message:
            raise RuntimeError("ReplicaSet did not record a Juardrails FailedCreate event")
        pods = json.loads(run(kube + ["get", "pods", "-n", args.namespace, "-l", "app=system-monitor", "-o", "json"]).stdout)["items"]
        if pods:
            raise RuntimeError("the vulnerable Kubernetes Goat Pod was created")
        print("Goat Deployment: created; child Pod denied with FailedCreate event; no Pod exists")
        observation = {"goat_commit": sha, "namespace": args.namespace, "scenario": "system-monitor",
                       "pod_dry_run": "denied_by_juardrails", "deployment": "created",
                       "child_pod": "denied_by_juardrails", "failed_create_event": True, "vulnerable_pod_count": 0}
        if args.output:
            args.output.write_text(json.dumps(observation, indent=2) + "\n")
    finally:
        if created:
            run(kube + ["delete", "deployment", name, "-n", args.namespace, "--wait=false"], check=False)


if __name__ == "__main__":
    main()

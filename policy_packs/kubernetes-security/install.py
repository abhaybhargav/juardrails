#!/usr/bin/env python3
"""Install the Juardrails admission demo on an explicit Kubernetes context."""

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
SYSTEM = "juardrails-system"


def run(argv, *, input_data=None, check=True):
    result = subprocess.run(argv, input=input_data, text=True, capture_output=True, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(argv[:4])} failed: {result.stderr.strip()[-600:]}")
    return result


def key_from_env(path):
    if os.environ.get("TYPESAFE_API_KEY"):
        return os.environ["TYPESAFE_API_KEY"]
    for line in path.read_text().splitlines() if path.exists() else []:
        if line.strip().startswith("TYPESAFE_API_KEY="):
            return line.split("=", 1)[1].strip().strip("'\"")
    raise RuntimeError("TYPESAFE_API_KEY is required in the environment or .env")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="explicit kubectl context")
    parser.add_argument("--kind-cluster", help="load locally built image into this kind cluster")
    parser.add_argument("--image", default="juardrails-admission:local")
    parser.add_argument("--skip-build", action="store_true", help="use an image already available to the cluster")
    parser.add_argument("--env-file", type=Path, default=REPO / ".env")
    args = parser.parse_args()
    if args.image == "juardrails-admission:local" and not args.kind_cluster:
        parser.error("--kind-cluster is needed for the default local image; otherwise pass --image and --skip-build")
    kube = ["kubectl", "--context", args.context]
    run(kube + ["cluster-info"])
    provider_key = key_from_env(args.env_file)
    if not args.skip_build:
        run(["docker", "build", "-f", str(ROOT / "Dockerfile"), "-t", args.image, str(REPO)])
    if args.kind_cluster:
        gopath = run(["go", "env", "GOPATH"]).stdout.strip().split(os.pathsep)[0]
        run([str(Path(gopath) / "bin/kind"), "load", "docker-image", args.image, "--name", args.kind_cluster])
    run(kube + ["create", "namespace", SYSTEM], check=False)
    with tempfile.TemporaryDirectory(prefix="juardrails-k8s-") as tmp:
        tmp = Path(tmp)
        (tmp / "provider-key").write_text(provider_key)
        os.chmod(tmp / "provider-key", 0o600)
        secret = run(kube + ["create", "secret", "generic", "juardrails-provider", "-n", SYSTEM,
                           "--from-file=TYPESAFE_API_KEY=" + str(tmp / "provider-key"), "--dry-run=client", "-o", "yaml"]).stdout
        run(kube + ["apply", "-f", "-"], input_data=secret)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365", "-subj", "/CN=Juardrails admission demo CA",
             "-keyout", str(tmp / "ca.key"), "-out", str(tmp / "ca.crt")])
        (tmp / "leaf.cnf").write_text("subjectAltName=DNS:juardrails-admission.juardrails-system.svc,DNS:juardrails-admission.juardrails-system.svc.cluster.local\nextendedKeyUsage=serverAuth\n")
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=juardrails-admission.juardrails-system.svc",
             "-keyout", str(tmp / "tls.key"), "-out", str(tmp / "tls.csr")])
        run(["openssl", "x509", "-req", "-in", str(tmp / "tls.csr"), "-CA", str(tmp / "ca.crt"), "-CAkey", str(tmp / "ca.key"),
             "-CAcreateserial", "-days", "365", "-extfile", str(tmp / "leaf.cnf"), "-out", str(tmp / "tls.crt")])
        tls = run(kube + ["create", "secret", "tls", "juardrails-admission-tls", "-n", SYSTEM,
                          "--cert", str(tmp / "tls.crt"), "--key", str(tmp / "tls.key"), "--dry-run=client", "-o", "yaml"]).stdout
        run(kube + ["apply", "-f", "-"], input_data=tls)
        manifest = (ROOT / "deploy/base.yaml").read_text().replace("juardrails-admission:local", args.image)
        run(kube + ["apply", "-f", "-"], input_data=manifest)
        # TLS is read at process startup; a Secret update alone does not replace the served certificate.
        run(kube + ["rollout", "restart", "deployment/juardrails-admission", "-n", SYSTEM])
        pod = ""
        for _ in range(120):
            replicasets = json.loads(run(kube + ["get", "replicasets", "-n", SYSTEM, "-l", "app=juardrails-admission", "-o", "json"]).stdout)["items"]
            newest = max(replicasets, key=lambda r: int(r["metadata"].get("annotations", {}).get("deployment.kubernetes.io/revision", "0")))["metadata"]["name"] if replicasets else ""
            found = run(kube + ["get", "pods", "-n", SYSTEM, "-l", "app=juardrails-admission", "-o", "json"])
            items = json.loads(found.stdout)["items"]
            for item in items:
                owners = [o["name"] for o in item["metadata"].get("ownerReferences", [])]
                if newest in owners and item["status"].get("phase") == "Running" and not item["metadata"].get("deletionTimestamp"):
                    pod = item["metadata"]["name"]
                    break
            if pod:
                break
            time.sleep(2)
        if not pod:
            raise RuntimeError("admission Pod did not start; inspect kubectl describe pod -n juardrails-system")

        def admin(*args, payload=None, check=True):
            return run(kube + ["exec", "-i", "-n", SYSTEM, pod, "-c", "server", "--", "juardrails", "cli", *args], input_data=payload, check=check)

        for _ in range(60):
            probe = admin("admin", "users", "list", check=False)
            if probe.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError("Juardrails API did not become ready")
        namespaces = json.loads(admin("admin", "namespaces", "list").stdout)["items"]
        if not any(n["name"] == "kubernetes-security" for n in namespaces):
            admin("admin", "namespaces", "create", "-", payload=json.dumps({"name": "kubernetes-security"}))
        admin("-namespace", "kubernetes-security", "apply", "-", payload=(ROOT / "policies/kubernetes-pod-security.yaml").read_text())
        grant = {"name": "kubernetes-admission-evaluator", "rules": [{"namespace": "kubernetes-security", "actions": ["policies:evaluate"]}]}
        grants = json.loads(admin("admin", "access", "list").stdout)["items"]
        if not any(g["name"] == grant["name"] for g in grants):
            admin("admin", "access", "create", "-", payload=json.dumps(grant))
        principals = json.loads(admin("admin", "users", "list").stdout)["items"]
        principal = next((p for p in principals if p["name"] == "kubernetes-admission"), None)
        if principal is None:
            principal = json.loads(admin("admin", "users", "create", "-", payload=json.dumps({"name": "kubernetes-admission", "kind": "service"})).stdout)
        elif principal["kind"] != "service":
            raise RuntimeError("existing kubernetes-admission identity is not a service account")
        admin("admin", "users", "bindings", principal["id"], "-", payload=json.dumps({"policies": [grant["name"]]}))
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat().replace("+00:00", "Z")
        previous = [t["id"] for t in json.loads(admin("admin", "tokens", "list").stdout)["items"]
                    if t.get("principal_id") == principal["id"]]
        issued = json.loads(admin("admin", "tokens", "create", "-", payload=json.dumps({"principal_id": principal["id"], "name": "admission-webhook", "expires_at": expiry})).stdout)
        credential = json.dumps({"url": "http://127.0.0.1:8080", "token": issued["token"]})
        run(kube + ["exec", "-i", "-n", SYSTEM, pod, "-c", "webhook", "--", "sh", "-c",
                    "umask 077; mkdir -p /home/juardrails/.juardrails; chmod 700 /home/juardrails/.juardrails; cat > /home/juardrails/.juardrails/credentials.json"], input_data=credential)
        restricted = run(kube + ["exec", "-n", SYSTEM, pod, "-c", "webhook", "--", "juardrails", "cli", "-namespace", "root", "list"], check=False)
        if restricted.returncode == 0:
            raise RuntimeError("admission identity unexpectedly has root namespace access")
        for token_id in previous:
            admin("admin", "tokens", "revoke", token_id)
        run(kube + ["rollout", "status", "deployment/juardrails-admission", "-n", SYSTEM, "--timeout=180s"])
        webhook = (ROOT / "deploy/webhook.yaml").read_text().replace("REPLACE_WITH_CA_BUNDLE", base64.b64encode((tmp / "ca.crt").read_bytes()).decode())
        run(kube + ["apply", "-f", "-"], input_data=webhook)
    print(f"Installed admission webhook on {args.context}. Label a test namespace juardrails.io/admission=enabled, then run smoke.py.")


if __name__ == "__main__":
    main()

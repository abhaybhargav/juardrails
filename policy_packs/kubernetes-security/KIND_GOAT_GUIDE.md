# Test Juardrails admission on Kind with Kubernetes Goat

This guide uses the real `system-monitor` workload from [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat), an intentionally vulnerable Kubernetes lab. That scenario requests host PID/IPC access, a `hostPath` mount of `/`, and a privileged container. Juardrails evaluates the Pod template through its restricted service-account CLI and denies admission. The fixed baseline also denies those settings even if a Jev answer is wrong.

The guide deploys **one Goat scenario template** in a dedicated namespace. It does not run Kubernetes Goat's complete setup script or install its cluster-wide RBAC examples. The original Goat manifest also contains a Secret and Service in `default`; the probe reads only its Deployment's Pod template. Nothing in this guide requires a vulnerable Goat container to start.

## 1. Prepare a disposable Kind cluster

Run these commands from the Juardrails repository root. You need Docker, Go, `kubectl`, Python 3, OpenSSL, and a TypeSafe API key in this repository's `.env` or `TYPESAFE_API_KEY` in the environment. Docker should have enough resources for one Kind node and the Juardrails image build.

```sh
go install sigs.k8s.io/kind@v0.30.0
"$(go env GOPATH)/bin/kind" create cluster --name juardrails-goat --wait 120s
kubectl --context kind-juardrails-goat get nodes
```

The explicit context in every following command prevents accidentally targeting another cluster.

## 2. Install Juardrails and its admission webhook

```sh
python3 policy_packs/kubernetes-security/install.py \
  --context kind-juardrails-goat --kind-cluster juardrails-goat
kubectl --context kind-juardrails-goat -n juardrails-system \
  rollout status deployment/juardrails-admission --timeout=180s
kubectl --context kind-juardrails-goat get validatingwebhookconfiguration \
  juardrails-pod-security
```

The installer builds and loads a local image, stores the provider key in a Kubernetes Secret, creates the Juardrails server and TLS webhook, applies the `kubernetes-pod-security` policy, and injects a separate `policies:evaluate` service token into the webhook's `~/.juardrails/credentials.json`. The webhook has `failurePolicy: Fail` and applies only to namespaces with `juardrails.io/admission=enabled`.

## 3. Fetch the tested Kubernetes Goat revision

The probe expects commit `723a0db478f050d173d23b4ce5044b65bce0bdd0`, so upstream manifest changes cannot silently alter the test.

```sh
mkdir -p /tmp/juardrails-kubernetes-goat
git -C /tmp/juardrails-kubernetes-goat init
git -C /tmp/juardrails-kubernetes-goat fetch --depth 1 \
  https://github.com/madhuakula/kubernetes-goat.git \
  723a0db478f050d173d23b4ce5044b65bce0bdd0
git -C /tmp/juardrails-kubernetes-goat checkout --detach FETCH_HEAD
```

You can inspect the [upstream scenario manifest at that revision](https://github.com/madhuakula/kubernetes-goat/blob/723a0db478f050d173d23b4ce5044b65bce0bdd0/scenarios/system-monitor/deployment.yaml) before running the probe. `goat_probe.py` reads that file and does not execute any Goat scripts.

## 4. Probe admission with the Goat workload

```sh
python3 policy_packs/kubernetes-security/goat_probe.py \
  --context kind-juardrails-goat \
  --goat-dir /tmp/juardrails-kubernetes-goat \
  --output /tmp/juardrails-goat-observed.json
```

Expected output:

```text
Goat Pod dry-run: denied by Juardrails webhook
Goat Deployment: created; child Pod denied with FailedCreate event; no Pod exists
```

The probe creates and labels `goat-guarded`, extracts the original Deployment's Pod spec, and sends a **server-side Pod dry run**. It asserts that Juardrails specifically denied it. It then creates a temporary Deployment from the same template. A Deployment object can be accepted because this webhook targets Pods; the ReplicaSet's attempt to create its child Pod is denied and produces a `FailedCreate` event. The probe checks that no `system-monitor` Pod exists and deletes the temporary Deployment. It leaves the namespace and event for inspection.

```sh
kubectl --context kind-juardrails-goat -n goat-guarded get pods
kubectl --context kind-juardrails-goat -n goat-guarded get events \
  --field-selector reason=FailedCreate --sort-by=.lastTimestamp
kubectl --context kind-juardrails-goat -n juardrails-system \
  exec deployment/juardrails-admission -c server -- \
  juardrails cli -namespace kubernetes-security history kubernetes-pod-security
```

The event should name `pod-security.juardrails.io` and list denied settings such as host namespaces, `hostPath`, and privileged mode. Juardrails history provides the policy revision, Jev answers, and evaluation duration. Controller retries can produce more than one evaluation record.

## 5. Run the pack's allow and deny controls

```sh
python3 policy_packs/kubernetes-security/smoke.py \
  --context kind-juardrails-goat \
  --output /tmp/juardrails-goat-smoke.json
```

This creates a second opt-in namespace, `juardrails-smoke`, and checks one hardened Pod and six unsafe variants through server-side dry runs. The script requires the hardened Pod to be admitted and every unsafe Pod to be denied **by Juardrails**, rather than merely failing Kubernetes schema validation. It exits nonzero if any result differs.

## Observed on 4 October 2026

On a fresh Kind v1.34.0 cluster with live TypeSafe Jev, the Goat Pod dry run was denied. The Goat Deployment was accepted, but its ReplicaSet recorded a Juardrails `FailedCreate` event and created zero Pods. Jev returned `block` for the Goat evaluations. The separate pack smoke suite matched all seven expected admissions. See [the sanitized Goat observation](goat-observed-results.json) and [the earlier pack smoke study](observed-results.json). This is a reproducible demonstration, not a general detection or latency benchmark; Jev answers may vary.

## Cleanup and limits

```sh
"$(go env GOPATH)/bin/kind" delete cluster --name juardrails-goat
```

Deleting this disposable cluster removes the copied provider key, evaluator token, policy database, and audit history. If a command fails, inspect the webhook Pod logs and readiness, the `juardrails-provider` Secret, the namespace label, the TLS webhook `caBundle`, and `FailedCreate` events. A provider outage fails closed in labeled namespaces. The pack checks Pod admission, so it does not prevent Goat's separate RBAC, SSRF, or application-level exercises. The demo uses one SQLite-backed Pod, a generated certificate, and a 30-day evaluator token; see the [pack operations notes](README.md) before using it beyond a lab.

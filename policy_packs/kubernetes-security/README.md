# Kubernetes security admission pack

This pack deploys Juardrails and a TLS validating admission webhook on Kubernetes. It applies a versioned Jev policy to Pod admission and keeps a deterministic security baseline in the webhook. **Admission requires both an explicit Juardrails `allow` and a clean baseline.** `block`, `review`, `error`, CLI failures, and provider outages deny the request. Only namespaces labeled `juardrails.io/admission=enabled` are affected.

The baseline draws on the concepts in [Kyverno's require-run-as-nonroot policy](https://kyverno.io/policies/pod-security/restricted/require-run-as-nonroot/require-run-as-nonroot/), [strict capability policy](https://kyverno.io/policies/pod-security/restricted/disallow-capabilities-strict/disallow-capabilities-strict/), and [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/). This is a Juardrails implementation, not a Kyverno policy translation or a replacement for Pod Security Admission.

## What it checks

- Denies privileged containers, privilege escalation, added capabilities, root execution, missing seccomp, host namespaces, hostPath, and hostPort. Checks regular, init, and ephemeral containers.
- Requires `automountServiceAccountToken: false`, `capabilities.drop: [ALL]`, and a versioned or digest-pinned image. The tag check does not verify image signatures or provenance.
- Sends a minimized Pod security view to Juardrails through `juardrails cli -namespace kubernetes-security evaluate kubernetes-pod-security -`. Command, environment values, annotations, and Secret contents are excluded. Jev returns criterion traces and a decision.

The webhook is scoped to Pod CREATE/UPDATE and the ephemeralcontainers subresource. Controllers are covered when they create child Pods; a server-side dry run of a Deployment alone does not create those Pods.

## Local kind demonstration

Prerequisites: Docker, `kubectl`, Go, Python 3, OpenSSL, and a TypeSafe API key in the repository `.env` or `TYPESAFE_API_KEY` in the environment. The installer builds a small image locally. It does not publish the image.

```sh
go install sigs.k8s.io/kind@v0.30.0
"$(go env GOPATH)/bin/kind" create cluster --name juardrails-admission
python3 policy_packs/kubernetes-security/install.py \
  --context kind-juardrails-admission --kind-cluster juardrails-admission
python3 policy_packs/kubernetes-security/smoke.py \
  --context kind-juardrails-admission --output /tmp/juardrails-kubernetes-smoke.json
```

The installer requires an explicit kube context. For an existing cluster, push the image to a registry and use `--image REGISTRY/juardrails:TAG --skip-build`; omit `--kind-cluster`. The cluster needs a default StorageClass. The installer creates `juardrails-system`, a 1 GiB PVC, a provider-key Secret, a TLS Secret, a one-replica Deployment and Service, and the `ValidatingWebhookConfiguration`. It bootstraps Juardrails, applies the policy, and gives the webhook its own service account with only `policies:evaluate` in `kubernetes-security`. Its CLI credential is injected at `/home/juardrails/.juardrails/credentials.json` on the PVC with directory mode 0700 and file mode 0600. The webhook talks to the Juardrails API over Pod localhost; no human session is used for evaluation. The installer verifies that this identity cannot list policies in `root`.

The installer generates a one-year demo CA and serving certificate. Re-running it rotates both and restarts the deployment before updating the webhook CA bundle. For long-lived clusters, manage certificate rotation, provider keys, SQLite backups, admission availability, and service-token rotation through your normal platform processes. The one-replica SQLite deployment is a demonstration, not a high-availability control plane. The evaluator token expires after 30 days; until rotated, the fail-closed webhook will deny opted-in Pod writes.

To remove only the demo policy scope, remove the label from a namespace. To remove the installation, delete `validatingwebhookconfiguration/juardrails-pod-security` first, then the `juardrails-system` namespace. PVC deletion removes policy and audit data; back it up if needed. For the disposable kind cluster, run `kind delete cluster --name juardrails-admission`.

## Observed cluster smoke test

On 2 October 2026, the pack ran on kind Kubernetes v1.34.0 with a live TypeSafe Jev 1.13.0 provider. The [sanitized results](observed-results.json) record seven API-server dry runs: one hardened Pod was admitted, and six unsafe variants were denied. A normal API create admitted the safe Pod; another normal create rejected a hostPath Pod. The policy was at revision 6 after calibration. The seven Juardrails provider evaluations ranged from 282 to 601 ms; end-to-end dry-run calls ranged from 385 to 728 ms. This is a small test run, not a latency or detection benchmark. Provider answers may change; test against your own workloads before enabling a namespace.

The dry-run suite asserts that each unsafe variant is rejected by **this webhook**, rather than merely failing Kubernetes schema validation. It exits nonzero if a case differs from its expected result. `go test ./internal/admission` checks the webhook's fail-closed decision path and baseline independently of the provider.

## Operational boundary

The Kubernetes API server validates the webhook's serving certificate using `caBundle`; the webhook configuration uses `failurePolicy: Fail` and `timeoutSeconds: 20`. Kubernetes documents the [AdmissionReview contract and failure behavior](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) and [webhook operating practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/). Only opt-in namespaces are matched, so system workloads do not depend on the external provider. The current pack evaluates every matched Pod, including baseline failures, so a provider outage blocks new Pods in opted-in namespaces.

The provider receives normalized Pod security settings and image references. Do not enable this pack for image names or workload metadata that cannot be sent to your configured provider. Any actor able to remove the namespace label, modify the webhook configuration, edit the Juardrails policy, or alter the Pod after admission through another route can change enforcement; restrict those permissions with Kubernetes RBAC and your cluster governance.

package kubernetessecurity

import "embed"

// Files contains the installable admission manifests and policy in the Juardrails binary.
//
//go:embed deploy/base.yaml deploy/webhook.yaml policies/kubernetes-pod-security.yaml
var Files embed.FS

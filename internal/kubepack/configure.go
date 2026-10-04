package kubepack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	pack "github.com/abhaybhargav/juardrails/policy_packs/kubernetes-security"
)

func (i *installer) waitPod(ctx context.Context) (string, error) {
	for attempt := 0; attempt < 120; attempt++ {
		rsBody, err := i.kube(ctx, nil, "get", "replicasets", "-n", systemNamespace, "-l", "app=juardrails-admission", "-o", "json")
		if err != nil {
			return "", err
		}
		var sets struct {
			Items []struct {
				Metadata struct {
					Name        string            `json:"name"`
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rsBody, &sets); err != nil {
			return "", fmt.Errorf("invalid ReplicaSet response: %w", err)
		}
		newest, revision := "", -1
		for _, item := range sets.Items {
			n, _ := strconv.Atoi(item.Metadata.Annotations["deployment.kubernetes.io/revision"])
			if n > revision {
				newest, revision = item.Metadata.Name, n
			}
		}
		podBody, err := i.kube(ctx, nil, "get", "pods", "-n", systemNamespace, "-l", "app=juardrails-admission", "-o", "json")
		if err != nil {
			return "", err
		}
		var pods struct {
			Items []struct {
				Metadata struct {
					Name              string `json:"name"`
					DeletionTimestamp string `json:"deletionTimestamp"`
					OwnerReferences   []struct {
						Name string `json:"name"`
					} `json:"ownerReferences"`
				} `json:"metadata"`
				Status struct {
					Phase string `json:"phase"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := json.Unmarshal(podBody, &pods); err != nil {
			return "", fmt.Errorf("invalid Pod response: %w", err)
		}
		for _, pod := range pods.Items {
			if newest == "" || pod.Status.Phase != "Running" || pod.Metadata.DeletionTimestamp != "" {
				continue
			}
			for _, owner := range pod.Metadata.OwnerReferences {
				if owner.Name == newest {
					return pod.Metadata.Name, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", errors.New("admission Pod did not start; inspect kubectl describe pod -n juardrails-system")
}

func items[T any](body []byte) ([]T, error) {
	var list struct {
		Items []T `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	if list.Items == nil {
		return nil, errors.New("missing items in Juardrails admin response")
	}
	return list.Items, nil
}

func (i *installer) configurePolicy(ctx context.Context) error {
	ready := false
	for attempt := 0; attempt < 60; attempt++ {
		if _, err := i.admin(ctx, nil, "admin", "users", "list"); err == nil {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if !ready {
		return errors.New("Juardrails API did not become ready")
	}
	body, err := i.admin(ctx, nil, "admin", "namespaces", "list")
	if err != nil {
		return err
	}
	namespaces, err := items[struct {
		Name string `json:"name"`
	}](body)
	if err != nil {
		return err
	}
	found := false
	for _, namespace := range namespaces {
		found = found || namespace.Name == "kubernetes-security"
	}
	if !found {
		if _, err := i.adminJSON(ctx, map[string]string{"name": "kubernetes-security"}, "admin", "namespaces", "create"); err != nil {
			return err
		}
	}
	policy, err := pack.Files.ReadFile("policies/kubernetes-pod-security.yaml")
	if err != nil {
		return err
	}
	if _, err := i.admin(ctx, policy, "-namespace", "kubernetes-security", "apply", "-"); err != nil {
		return err
	}
	grant := map[string]any{"name": "kubernetes-admission-evaluator", "rules": []any{map[string]any{
		"namespace": "kubernetes-security", "actions": []string{"policies:evaluate"},
	}}}
	body, err = i.admin(ctx, nil, "admin", "access", "list")
	if err != nil {
		return err
	}
	grants, err := items[struct {
		Name string `json:"name"`
	}](body)
	if err != nil {
		return err
	}
	found = false
	for _, existing := range grants {
		found = found || existing.Name == "kubernetes-admission-evaluator"
	}
	if found {
		grantBody, err := json.Marshal(grant)
		if err != nil {
			return err
		}
		if _, err := i.admin(ctx, grantBody, "admin", "access", "update", "-", "kubernetes-admission-evaluator"); err != nil {
			return err
		}
	} else if _, err := i.adminJSON(ctx, grant, "admin", "access", "create"); err != nil {
		return err
	}
	body, err = i.admin(ctx, nil, "admin", "users", "list")
	if err != nil {
		return err
	}
	principals, err := items[struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	}](body)
	if err != nil {
		return err
	}
	principalID := ""
	for _, principal := range principals {
		if principal.Name != "kubernetes-admission" {
			continue
		}
		if principal.Kind != "service" {
			return errors.New("existing kubernetes-admission identity is not a service account")
		}
		principalID = principal.ID
		break
	}
	if principalID == "" {
		body, err = i.adminJSON(ctx, map[string]string{"name": "kubernetes-admission", "kind": "service"}, "admin", "users", "create")
		if err != nil {
			return err
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			return errors.New("invalid service account creation response")
		}
		principalID = created.ID
	}
	if _, err := i.adminJSON(ctx, map[string][]string{"policies": {"kubernetes-admission-evaluator"}}, "admin", "users", "bindings", principalID); err != nil {
		return err
	}
	body, err = i.admin(ctx, nil, "admin", "tokens", "list")
	if err != nil {
		return err
	}
	tokens, err := items[struct {
		ID          string `json:"id"`
		PrincipalID string `json:"principal_id"`
	}](body)
	if err != nil {
		return err
	}
	previous := []string{}
	for _, token := range tokens {
		if token.PrincipalID == principalID {
			previous = append(previous, token.ID)
		}
	}
	body, err = i.adminJSON(ctx, map[string]string{
		"principal_id": principalID,
		"name":         "admission-webhook",
		"expires_at":   time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}, "admin", "tokens", "create")
	if err != nil {
		return err
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &issued); err != nil || issued.Token == "" {
		return errors.New("invalid evaluator token response")
	}
	credential, err := json.Marshal(map[string]string{"url": "http://127.0.0.1:8080", "token": issued.Token})
	if err != nil {
		return err
	}
	// Server and webhook share the PVC. Write as UID 10001 without exposing the token in arguments.
	if _, err = i.kube(ctx, credential, "exec", "-i", "-n", systemNamespace, i.podName, "-c", "server", "--", "sh", "-ec",
		"umask 077; mkdir -p /data/agent-home/.juardrails; chmod 700 /data/agent-home/.juardrails; cat > /data/agent-home/.juardrails/credentials.json"); err != nil {
		return err
	}
	if _, err := i.kube(ctx, nil, "exec", "-n", systemNamespace, i.podName, "-c", "webhook", "--", "juardrails", "cli", "request", "GET", "/auth/me"); err != nil {
		return fmt.Errorf("admission service credential could not authenticate: %w", err)
	}
	if _, err := i.kube(ctx, nil, "exec", "-n", systemNamespace, i.podName, "-c", "webhook", "--", "juardrails", "cli", "-namespace", "root", "list"); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		return errors.New("admission identity root namespace restriction could not be verified")
	}
	for _, id := range previous {
		if _, err := i.admin(ctx, nil, "admin", "tokens", "revoke", id); err != nil {
			return err
		}
	}
	return nil
}

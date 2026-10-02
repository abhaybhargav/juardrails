package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxReviewBytes = 1 << 20

type review struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Request    *request  `json:"request,omitempty"`
	Response   *response `json:"response,omitempty"`
}
type request struct {
	UID       string `json:"uid"`
	Operation string `json:"operation"`
	Kind      struct {
		Kind string `json:"kind"`
	} `json:"kind"`
	Resource struct {
		Resource string `json:"resource"`
	} `json:"resource"`
	Object json.RawMessage `json:"object"`
}
type response struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}
type status struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type pod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec podSpec `json:"spec"`
}
type podSpec struct {
	HostNetwork                  bool  `json:"hostNetwork"`
	HostPID                      bool  `json:"hostPID"`
	HostIPC                      bool  `json:"hostIPC"`
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
	SecurityContext              struct {
		RunAsNonRoot   *bool `json:"runAsNonRoot"`
		SeccompProfile *struct {
			Type string `json:"type"`
		} `json:"seccompProfile"`
	} `json:"securityContext"`
	Volumes []struct {
		HostPath json.RawMessage `json:"hostPath"`
	} `json:"volumes"`
	Containers          []container `json:"containers"`
	InitContainers      []container `json:"initContainers"`
	EphemeralContainers []container `json:"ephemeralContainers"`
}
type container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ports []struct {
		HostPort int `json:"hostPort"`
	} `json:"ports"`
	SecurityContext *struct {
		Privileged               *bool  `json:"privileged"`
		AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
		RunAsNonRoot             *bool  `json:"runAsNonRoot"`
		RunAsUser                *int64 `json:"runAsUser"`
		SeccompProfile           *struct {
			Type string `json:"type"`
		} `json:"seccompProfile"`
		Capabilities *struct {
			Add  []string `json:"add"`
			Drop []string `json:"drop"`
		} `json:"capabilities"`
	} `json:"securityContext"`
}

// Evaluator is the service-account CLI boundary. Only an explicit allow is authorizing.
type Evaluator func(context.Context, []byte) (string, error)

func CLI(binary, namespace, policy string, timeout time.Duration) Evaluator {
	return func(ctx context.Context, state []byte) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "cli", "-namespace", namespace, "evaluate", policy, "-")
		cmd.Stdin = bytes.NewReader(state)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			return "", err
		}
		if out.Len() > maxReviewBytes {
			return "", errors.New("evaluation response too large")
		}
		var result struct {
			Decision  string `json:"decision"`
			PolicyID  string `json:"policy_id"`
			Namespace string `json:"namespace"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			return "", err
		}
		if result.PolicyID != policy || result.Namespace != namespace {
			return "", errors.New("evaluation identity mismatch")
		}
		return result.Decision, nil
	}
}

func Handler(evaluate Evaluator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReviewBytes))
		if err != nil {
			http.Error(w, "review too large", http.StatusRequestEntityTooLarge)
			return
		}
		var input review
		if json.Unmarshal(body, &input) != nil || input.APIVersion != "admission.k8s.io/v1" || input.Kind != "AdmissionReview" || input.Request == nil || input.Request.UID == "" {
			http.Error(w, "invalid AdmissionReview", http.StatusBadRequest)
			return
		}
		out := review{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview", Response: &response{UID: input.Request.UID}}
		deny := func(message string) { out.Response.Status = &status{Code: http.StatusForbidden, Message: message} }
		switch {
		case input.Request.Kind.Kind != "Pod" || input.Request.Resource.Resource != "pods" && input.Request.Resource.Resource != "pods/ephemeralcontainers":
			deny("unsupported admission resource")
		case input.Request.Operation != "CREATE" && input.Request.Operation != "UPDATE":
			deny("unsupported admission operation")
		default:
			var obj pod
			if json.Unmarshal(input.Request.Object, &obj) != nil || len(obj.Spec.Containers) == 0 {
				deny("invalid Pod object")
			} else {
				violations := CheckPod(obj.Spec)
				state, err := json.Marshal(map[string]any{"state": map[string]any{"kind": "Pod", "name": obj.Metadata.Name, "namespace": obj.Metadata.Namespace, "pod_spec": obj.Spec, "deterministic_violations": violations}})
				if err != nil {
					deny("cannot prepare evaluation")
				} else {
					decision, err := evaluate(r.Context(), state)
					switch {
					case err != nil:
						deny("Juardrails policy evaluation unavailable")
					case len(violations) > 0:
						deny("Kubernetes security baseline: " + strings.Join(violations, "; "))
					case decision != "allow":
						deny("Juardrails policy decision: " + decision)
					default:
						out.Response.Allowed = true
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
}

// CheckPod enforces a non-bypassable baseline inspired by Kyverno restricted Pod policies.
func CheckPod(s podSpec) []string {
	var bad []string
	if s.HostNetwork || s.HostPID || s.HostIPC {
		bad = append(bad, "host namespaces are forbidden")
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken {
		bad = append(bad, "service-account token automount must be false")
	}
	for _, v := range s.Volumes {
		if len(v.HostPath) > 0 && string(v.HostPath) != "null" {
			bad = append(bad, "hostPath volumes are forbidden")
			break
		}
	}
	containers := append([]container{}, s.Containers...)
	containers = append(containers, s.InitContainers...)
	containers = append(containers, s.EphemeralContainers...)
	for _, c := range containers {
		name := c.Name
		if name == "" {
			name = "unnamed"
		}
		if c.SecurityContext == nil {
			bad = append(bad, fmt.Sprintf("%s: securityContext required", name))
			continue
		}
		sec := c.SecurityContext
		if sec.Privileged != nil && *sec.Privileged {
			bad = append(bad, fmt.Sprintf("%s: privileged container", name))
		}
		if sec.AllowPrivilegeEscalation == nil || *sec.AllowPrivilegeEscalation {
			bad = append(bad, fmt.Sprintf("%s: privilege escalation must be false", name))
		}
		nonroot := s.SecurityContext.RunAsNonRoot != nil && *s.SecurityContext.RunAsNonRoot
		if sec.RunAsNonRoot != nil {
			nonroot = *sec.RunAsNonRoot
		}
		if !nonroot || sec.RunAsUser != nil && *sec.RunAsUser == 0 {
			bad = append(bad, fmt.Sprintf("%s: must run as non-root", name))
		}
		profile := s.SecurityContext.SeccompProfile
		if sec.SeccompProfile != nil {
			profile = sec.SeccompProfile
		}
		if profile == nil || profile.Type != "RuntimeDefault" && profile.Type != "Localhost" {
			bad = append(bad, fmt.Sprintf("%s: seccomp profile required", name))
		}
		if sec.Capabilities == nil || len(sec.Capabilities.Add) > 0 || !containsFold(sec.Capabilities.Drop, "ALL") {
			bad = append(bad, fmt.Sprintf("%s: drop all capabilities", name))
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				bad = append(bad, fmt.Sprintf("%s: hostPort forbidden", name))
				break
			}
		}
		imageName := c.Image[strings.LastIndex(c.Image, "/")+1:]
		tag := ""
		if pos := strings.LastIndex(imageName, ":"); pos >= 0 {
			tag = imageName[pos+1:]
		}
		if c.Image == "" || tag == "latest" || tag == "" && !strings.Contains(c.Image, "@sha256:") {
			bad = append(bad, fmt.Sprintf("%s: use a versioned image", name))
		}
	}
	return bad
}
func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func Ready(path string) bool { _, err := os.Stat(path); return err == nil }

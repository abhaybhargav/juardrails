package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const safePod = `{"metadata":{"name":"safe","namespace":"guarded"},"spec":{"automountServiceAccountToken":false,"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"app","image":"busybox:1.36","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}`

func invoke(t *testing.T, object string, evaluator Evaluator) review {
	t.Helper()
	input := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"test-uid","operation":"CREATE","kind":{"kind":"Pod"},"resource":{"resource":"pods"},"object":` + object + `}}`
	r := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(input))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	Handler(evaluator).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var out review
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Response == nil || out.Response.UID != "test-uid" {
		t.Fatalf("invalid response: %s", w.Body.String())
	}
	return out
}

func TestAdmissionRequiresBothJevAllowAndBaseline(t *testing.T) {
	allow := func(_ context.Context, input []byte) (string, error) {
		if !bytes.Contains(input, []byte(`"image":"busybox:1.36"`)) {
			t.Fatal("normalized pod not sent to CLI")
		}
		return "allow", nil
	}
	if !invoke(t, safePod, allow).Response.Allowed {
		t.Fatal("safe pod blocked")
	}
	for _, alteration := range []string{
		`"privileged":true,`,
		`"runAsUser":0,`,
		`"capabilities":{"add":["SYS_ADMIN"],"drop":["ALL"]},`,
	} {
		obj := strings.Replace(safePod, `"allowPrivilegeEscalation":false,`, alteration+`"allowPrivilegeEscalation":false,`, 1)
		if invoke(t, obj, allow).Response.Allowed {
			t.Fatalf("unsafe pod allowed: %s", alteration)
		}
	}
	for _, spec := range []string{`"hostNetwork":true,`, `"volumes":[{"hostPath":{"path":"/"}}],`} {
		obj := strings.Replace(safePod, `"spec":{`, `"spec":{`+spec, 1)
		if invoke(t, obj, allow).Response.Allowed {
			t.Fatalf("unsafe pod allowed: %s", spec)
		}
	}
	untaggedRegistry := strings.Replace(safePod, "busybox:1.36", "registry.example:5000/app", 1)
	if invoke(t, untaggedRegistry, func(context.Context, []byte) (string, error) { return "allow", nil }).Response.Allowed {
		t.Fatal("accepted an untagged image because its registry includes a port")
	}
	blankTag := strings.Replace(safePod, "busybox:1.36", "busybox:", 1)
	if invoke(t, blankTag, func(context.Context, []byte) (string, error) { return "allow", nil }).Response.Allowed {
		t.Fatal("accepted an empty image tag")
	}
	initPrivilege := strings.Replace(safePod, `"containers":[`, `"initContainers":[{"name":"init","image":"busybox:1.36","securityContext":{"privileged":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}],"containers":[`, 1)
	if invoke(t, initPrivilege, func(context.Context, []byte) (string, error) { return "allow", nil }).Response.Allowed {
		t.Fatal("accepted a privileged init container")
	}
	if invoke(t, safePod, func(context.Context, []byte) (string, error) { return "review", nil }).Response.Allowed {
		t.Fatal("review allowed")
	}
	if invoke(t, safePod, func(context.Context, []byte) (string, error) { return "", errors.New("provider down") }).Response.Allowed {
		t.Fatal("provider outage allowed")
	}
}

func TestAdmissionRejectsInvalidInput(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(`{"apiVersion":"admission.k8s.io/v1"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	Handler(nil).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d", w.Code)
	}
}

package kubepack

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBundledManifestsAndTLS(t *testing.T) {
	base, err := renderBase("registry.example/juardrails:v1")
	if err != nil || bytes.Count(base, []byte("image: \"registry.example/juardrails:v1\"")) != 3 {
		t.Fatalf("render deployment: %v", err)
	}
	ca, cert, key, err := generateTLS(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(ca)
	certBlock, _ := pem.Decode(cert)
	keyBlock, _ := pem.Decode(key)
	if caBlock == nil || certBlock == nil || keyBlock == nil {
		t.Fatal("missing PEM block")
	}
	issuer, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "juardrails-admission.juardrails-system.svc"}); err != nil {
		t.Fatalf("serving certificate does not verify: %v", err)
	}
	webhook, err := renderWebhook(ca)
	if err != nil || !bytes.Contains(webhook, []byte(base64.StdEncoding.EncodeToString(ca))) {
		t.Fatalf("render webhook CA: %v", err)
	}
}

func TestInstallSequenceKeepsCredentialOutOfArguments(t *testing.T) {
	var calls []string
	var credential []byte
	var webhook []byte
	fake := func(ctx context.Context, argv []string, input []byte) ([]byte, error) {
		joined := strings.Join(argv, " ")
		calls = append(calls, joined)
		if strings.Contains(joined, "provider-secret-for-test") || strings.Contains(joined, "issued-token-for-test") {
			t.Fatal("secret appeared in command arguments")
		}
		switch {
		case strings.Contains(joined, "get replicasets"):
			return []byte(`{"items":[{"metadata":{"name":"new-rs","annotations":{"deployment.kubernetes.io/revision":"2"}}}]}`), nil
		case strings.Contains(joined, "get pods"):
			return []byte(`{"items":[{"metadata":{"name":"new-pod","ownerReferences":[{"name":"new-rs"}]},"status":{"phase":"Running"}}]}`), nil
		case strings.Contains(joined, "admin namespaces list"):
			return []byte(`{"items":[{"name":"root"}]}`), nil
		case strings.Contains(joined, "admin access list"):
			return []byte(`{"items":[]}`), nil
		case strings.Contains(joined, "admin users list"):
			return []byte(`{"items":[{"id":"admin","name":"cli-admin","kind":"service"}]}`), nil
		case strings.Contains(joined, "admin users create"):
			return []byte(`{"id":"admission-id"}`), nil
		case strings.Contains(joined, "admin tokens list"):
			return []byte(`{"items":[{"id":"old-token","principal_id":"admission-id"}]}`), nil
		case strings.Contains(joined, "admin tokens create"):
			return []byte(`{"token":"issued-token-for-test"}`), nil
		case strings.Contains(joined, "-c webhook -- juardrails cli -namespace root list"):
			return nil, errors.New("HTTP 403: forbidden")
		case strings.Contains(joined, "-c server -- sh -ec"):
			credential = bytes.Clone(input)
		case strings.HasSuffix(joined, "apply -f -") && bytes.Contains(input, []byte("kind: ValidatingWebhookConfiguration")):
			webhook = bytes.Clone(input)
		case strings.Contains(joined, "create secret"):
			return []byte("apiVersion: v1\nkind: Secret\n"), nil
		}
		return []byte("{}"), nil
	}
	i := &installer{options: options{context: "kind-demo", image: "registry.example/juardrails:v1"}, run: fake}
	if err := i.install(context.Background(), "provider-secret-for-test"); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed["token"] != "issued-token-for-test" {
		t.Fatalf("missing injected service credential: %v", err)
	}
	if !bytes.Contains(webhook, []byte("caBundle:")) || bytes.Contains(webhook, []byte("REPLACE_WITH_CA_BUNDLE")) {
		t.Fatal("webhook CA was not installed")
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "admin tokens revoke old-token") || !strings.Contains(joined, "admin namespaces create -") || !strings.Contains(joined, "-namespace kubernetes-security apply -") {
		t.Fatal("install did not complete policy setup and token rotation")
	}
	if strings.Index(joined, "admin tokens revoke old-token") > strings.LastIndex(joined, "apply -f -") {
		t.Fatal("token revocation happened after webhook activation")
	}
}

func TestInstallRequiresExplicitTarget(t *testing.T) {
	for _, args := range [][]string{{"kubernetes", "install"}, {"kubernetes", "install", "--context", "kind-demo"}} {
		if err := Run(args); err == nil {
			t.Fatalf("Run(%v) unexpectedly succeeded", args)
		}
	}
}

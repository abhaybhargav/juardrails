package kubepack

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abhaybhargav/juardrails/internal/config"
	pack "github.com/abhaybhargav/juardrails/policy_packs/kubernetes-security"
)

const systemNamespace = "juardrails-system"

type options struct {
	context      string
	kindCluster  string
	image        string
	buildContext string
	envFile      string
}

type runner func(context.Context, []string, []byte) ([]byte, error)

type installer struct {
	options
	run     runner
	podName string
}

// Run installs a bundled policy pack with the Juardrails executable.
func Run(args []string) error {
	if len(args) < 2 || args[0] != "kubernetes" || args[1] != "install" {
		return errors.New("usage: juardrails pack kubernetes install --context NAME --image IMAGE [--build-context PATH] [--kind-cluster NAME] [--env-file PATH]")
	}
	fs := flag.NewFlagSet("pack kubernetes install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var o options
	fs.StringVar(&o.context, "context", "", "explicit kubectl context (required)")
	fs.StringVar(&o.kindCluster, "kind-cluster", "", "kind cluster into which to load the local image")
	fs.StringVar(&o.image, "image", "", "container image (defaults to juardrails-admission:local with --build-context)")
	fs.StringVar(&o.buildContext, "build-context", "", "Juardrails source checkout for a local Docker image build")
	fs.StringVar(&o.envFile, "env-file", ".env", "dotenv file containing TYPESAFE_API_KEY when not in the environment")
	if err := fs.Parse(args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || o.context == "" {
		return errors.New("an explicit --context is required and no positional arguments are accepted")
	}
	if o.image == "" {
		if o.buildContext == "" {
			return errors.New("--image is required unless --build-context is set")
		}
		o.image = "juardrails-admission:local"
	}
	if strings.ContainsAny(o.image, "\r\n\t") || strings.TrimSpace(o.image) != o.image {
		return errors.New("invalid image reference")
	}
	if o.image == "juardrails-admission:local" && o.kindCluster == "" {
		return errors.New("the local image requires --kind-cluster; otherwise use a registry image")
	}
	if err := config.LoadEnv(o.envFile); err != nil {
		return err
	}
	providerKey := os.Getenv("TYPESAFE_API_KEY")
	if providerKey == "" {
		return errors.New("TYPESAFE_API_KEY is required in the environment or env file")
	}
	ctx := context.Background()
	return (&installer{options: o, run: execute}).install(ctx, providerKey)
}

func execute(parent context.Context, argv []string, input []byte) ([]byte, error) {
	deadline := 4 * time.Minute
	if argv[0] == "docker" {
		deadline = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s timed out", argv[0])
		}
		// Neither submitted state nor credentials appear in this message.
		message := strings.TrimSpace(stderr.String())
		if len(message) > 1200 {
			message = message[len(message)-1200:]
		}
		return nil, fmt.Errorf("%s command failed: %s", argv[0], message)
	}
	return out, nil
}

func (i *installer) command(ctx context.Context, input []byte, argv ...string) ([]byte, error) {
	return i.run(ctx, argv, input)
}

func (i *installer) kube(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	return i.command(ctx, input, append([]string{"kubectl", "--context", i.context}, args...)...)
}

func (i *installer) admin(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	cmd := []string{"exec", "-i", "-n", systemNamespace, i.podName, "-c", "server", "--", "juardrails", "cli"}
	return i.kube(ctx, input, append(cmd, args...)...)
}

func (i *installer) adminJSON(ctx context.Context, value any, args ...string) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return i.admin(ctx, body, append(args, "-")...)
}

func (i *installer) install(ctx context.Context, providerKey string) error {
	fmt.Fprintf(os.Stderr, "Checking Kubernetes context %s...\n", i.context)
	if _, err := i.kube(ctx, nil, "cluster-info"); err != nil {
		return fmt.Errorf("kubectl context %q is unavailable: %w", i.context, err)
	}
	if i.buildContext != "" {
		fmt.Fprintln(os.Stderr, "Building the Juardrails admission image...")
		contextPath, err := filepath.Abs(i.buildContext)
		if err != nil {
			return err
		}
		dockerfile := filepath.Join(contextPath, "policy_packs", "kubernetes-security", "Dockerfile")
		if _, err := os.Stat(dockerfile); err != nil {
			return fmt.Errorf("--build-context must point to the Juardrails repository: %w", err)
		}
		if _, err := i.command(ctx, nil, "docker", "build", "-f", dockerfile, "-t", i.image, contextPath); err != nil {
			return err
		}
	}
	if i.kindCluster != "" {
		fmt.Fprintf(os.Stderr, "Loading image into Kind cluster %s...\n", i.kindCluster)
		kind, err := kindBinary()
		if err != nil {
			return err
		}
		if _, err := i.command(ctx, nil, kind, "load", "docker-image", i.image, "--name", i.kindCluster); err != nil {
			return err
		}
	}
	if _, err := i.kube(ctx, []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: "+systemNamespace+"\n"), "apply", "-f", "-"); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Installing Juardrails, policy, and webhook...")
	if err := i.installResources(ctx, providerKey); err != nil {
		return err
	}
	fmt.Printf("Installed Kubernetes security admission on %s. Label a test namespace juardrails.io/admission=enabled before probing.\n", i.context)
	return nil
}

func kindBinary() (string, error) {
	if path, err := exec.LookPath("kind"); err == nil {
		return path, nil
	}
	dirs := filepath.SplitList(os.Getenv("GOPATH"))
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go"))
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, "bin", "kind")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", errors.New("kind executable not found; install kind or add it to PATH")
}

func (i *installer) installResources(ctx context.Context, providerKey string) error {
	tmp, err := os.MkdirTemp("", "juardrails-kubernetes-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	keyPath := filepath.Join(tmp, "provider-key")
	if err := os.WriteFile(keyPath, []byte(providerKey), 0600); err != nil {
		return err
	}
	secret, err := i.kube(ctx, nil, "create", "secret", "generic", "juardrails-provider", "-n", systemNamespace,
		"--from-file=TYPESAFE_API_KEY="+keyPath, "--dry-run=client", "-o", "yaml")
	if err != nil {
		return err
	}
	if _, err = i.kube(ctx, secret, "apply", "-f", "-"); err != nil {
		return err
	}
	ca, cert, key, err := generateTLS(time.Now())
	if err != nil {
		return err
	}
	certPath, keyFile := filepath.Join(tmp, "tls.crt"), filepath.Join(tmp, "tls.key")
	if err = os.WriteFile(certPath, cert, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(keyFile, key, 0600); err != nil {
		return err
	}
	tls, err := i.kube(ctx, nil, "create", "secret", "tls", "juardrails-admission-tls", "-n", systemNamespace,
		"--cert", certPath, "--key", keyFile, "--dry-run=client", "-o", "yaml")
	if err != nil {
		return err
	}
	if _, err = i.kube(ctx, tls, "apply", "-f", "-"); err != nil {
		return err
	}
	manifest, err := renderBase(i.image)
	if err != nil {
		return err
	}
	if _, err = i.kube(ctx, manifest, "apply", "-f", "-"); err != nil {
		return err
	}
	if _, err = i.kube(ctx, nil, "rollout", "restart", "deployment/juardrails-admission", "-n", systemNamespace); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Waiting for the admission Pod...")
	pod, err := i.waitPod(ctx)
	if err != nil {
		return err
	}
	i.podName = pod
	fmt.Fprintln(os.Stderr, "Applying policy and restricted service credentials...")
	if err = i.configurePolicy(ctx); err != nil {
		return err
	}
	if _, err = i.kube(ctx, nil, "rollout", "status", "deployment/juardrails-admission", "-n", systemNamespace, "--timeout=180s"); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Registering the validating webhook...")
	webhook, err := renderWebhook(ca)
	if err != nil {
		return err
	}
	_, err = i.kube(ctx, webhook, "apply", "-f", "-")
	return err
}

func renderBase(image string) ([]byte, error) {
	manifest, err := pack.Files.ReadFile("deploy/base.yaml")
	if err != nil {
		return nil, err
	}
	old := []byte("image: juardrails-admission:local")
	if bytes.Count(manifest, old) != 3 {
		return nil, errors.New("unexpected bundled deployment manifest")
	}
	return bytes.ReplaceAll(manifest, old, []byte("image: "+strconv.Quote(image))), nil
}

func renderWebhook(ca []byte) ([]byte, error) {
	manifest, err := pack.Files.ReadFile("deploy/webhook.yaml")
	if err != nil {
		return nil, err
	}
	old := []byte("REPLACE_WITH_CA_BUNDLE")
	if bytes.Count(manifest, old) != 1 {
		return nil, errors.New("unexpected bundled webhook manifest")
	}
	return bytes.Replace(manifest, old, []byte(base64.StdEncoding.EncodeToString(ca)), 1), nil
}

func generateTLS(now time.Time) (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	caTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Juardrails admission demo CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "juardrails-admission.juardrails-system.svc"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"juardrails-admission.juardrails-system.svc", "juardrails-admission.juardrails-system.svc.cluster.local"}}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

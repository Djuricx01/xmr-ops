package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposePortExposureDetection(t *testing.T) {
	report := runFixture(t, "example-bad")
	f := findingByID(t, report, "wallet_rpc_no_auth")
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", f.Severity)
	}
	if !findingEvidenceContains(f, "18082:18082") {
		t.Fatalf("expected compose port evidence, got %#v", f.Evidence)
	}
}

func TestDisableRPCLoginDetection(t *testing.T) {
	st := stateForFixture(t, "example-bad")
	ev := rpcLoginDisabled(st)
	if len(ev) == 0 {
		t.Fatal("disable-rpc-login not detected")
	}
	if !evidenceContains(ev, "DISABLE_RPC_LOGIN=true") && !evidenceContains(ev, "--disable-rpc-login") {
		t.Fatalf("unexpected evidence: %#v", ev)
	}
}

func TestLocalhostBindDetection(t *testing.T) {
	st := stateForFixture(t, "example-ok")
	if ev := walletLocalhostBind(st); len(ev) == 0 {
		t.Fatal("localhost wallet-rpc bind not detected")
	}
	if ev := walletPublicExposure(st); len(ev) != 0 {
		t.Fatalf("localhost publish treated as public: %#v", ev)
	}
}

func TestPublicBindDetection(t *testing.T) {
	st := stateForFixture(t, "example-bad")
	if ev := walletPublicExposure(st); len(ev) == 0 {
		t.Fatal("public wallet-rpc bind not detected")
	}
	if ev := monerodPublicExposure(st); len(ev) == 0 {
		t.Fatal("public monerod bind not detected")
	}
}

func TestFilePermissionClassification(t *testing.T) {
	tests := []struct {
		name string
		kind permKind
		mode uint32
		want Severity
	}{
		{"env 0600", permEnv, 0600, SeverityPass},
		{"env 0644", permEnv, 0644, SeverityWarn},
		{"wallet 0600", permWallet, 0600, SeverityPass},
		{"wallet 0640", permWallet, 0640, SeverityWarn},
		{"config 0640", permConfig, 0640, SeverityPass},
		{"config 0644", permConfig, 0644, SeverityWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyMode(tt.kind, os.FileMode(tt.mode), false, true)
			if got != tt.want {
				t.Fatalf("classifyMode = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestWebhookSecretDetection(t *testing.T) {
	lines := []string{
		"PAYMENT_WEBHOOK=https://merchant.example/callback",
		"WEBHOOK_SECRET=keep-local",
	}
	if !hasWebhookSecret(lines) {
		t.Fatal("webhook secret not detected")
	}
}

func TestSecretRedaction(t *testing.T) {
	got := RedactText("RPC_PASSWORD=super-secret")
	if strings.Contains(got, "super-secret") {
		t.Fatalf("secret was not redacted: %q", got)
	}
	if got != "RPC_PASSWORD=<redacted>" {
		t.Fatalf("redaction = %q", got)
	}
}

func TestWindowsPermissionFallback(t *testing.T) {
	got := classifyMode(permWallet, os.FileMode(0600), true, true)
	if got != SeverityReview {
		t.Fatalf("windows fallback = %s, want review", got)
	}
}

func TestBadFixtureExpectedPosture(t *testing.T) {
	report := runFixture(t, "example-bad")
	assertSeverity(t, report, "wallet_rpc_no_auth", SeverityCritical)
	assertSeverity(t, report, "webhook_auth", SeverityWarn)
	assertSeverity(t, report, "backup_signal", SeverityWarn)
	assertSeverity(t, report, "firewall_signal", SeverityWarn)

	docker := findingByID(t, report, "docker_socket_risk")
	priv := findingByID(t, report, "container_privilege_risk")
	if docker.Severity != SeverityWarn && priv.Severity != SeverityWarn {
		t.Fatalf("expected docker socket or privilege warning, got %s and %s", docker.Severity, priv.Severity)
	}
}

func TestMonerodVersionReviewsMixedPinnedAndUnpinnedImages(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "compose.yml", `services:
  monerod:
    image: ghcr.io/sethforprivacy/simple-monerod:v0.18.3.4
  wallet-rpc:
    image: monero-wallet-rpc:latest
`)

	report, err := Run(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	assertSeverity(t, report, "monerod_version", SeverityReview)
}

func TestBackupSignalIgnoresRestartPolicy(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "compose.yml", `services:
  monerod:
    image: ghcr.io/sethforprivacy/simple-monerod:v0.18.3.4
    restart: unless-stopped
`)

	report, err := Run(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	assertSeverity(t, report, "backup_signal", SeverityWarn)
}

func writeFixtureFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func runFixture(t *testing.T, name string) Report {
	t.Helper()
	report, err := Run(context.Background(), Options{Root: fixtureRoot(name)})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func stateForFixture(t *testing.T, name string) state {
	t.Helper()
	st, err := buildState(Options{Root: fixtureRoot(name)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func fixtureRoot(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func findingByID(t *testing.T, report Report, id string) Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.CheckID == id {
			return finding
		}
	}
	t.Fatalf("finding %s not found", id)
	return Finding{}
}

func assertSeverity(t *testing.T, report Report, id string, want Severity) {
	t.Helper()
	got := findingByID(t, report, id).Severity
	if got != want {
		t.Fatalf("%s severity = %s, want %s", id, got, want)
	}
}

func findingEvidenceContains(f Finding, text string) bool {
	return evidenceContains(f.Evidence, text)
}

func evidenceContains(ev []Evidence, text string) bool {
	for _, item := range ev {
		if strings.Contains(item.Text, text) {
			return true
		}
	}
	return false
}

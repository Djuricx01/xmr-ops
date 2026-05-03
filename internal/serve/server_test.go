package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"xmr-ops/internal/audit"
)

func TestHealthHandler(t *testing.T) {
	handler := NewHandler(Options{
		Audit: audit.Options{Root: fixtureRoot("example-ok")},
		Addr:  DefaultAddr,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
		Root    string `json:"root"`
		Time    string `json:"time"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || got.Version != audit.Version || got.Root == "" || got.Time == "" {
		t.Fatalf("unexpected health response: %#v", got)
	}
}

func TestAuditHandler(t *testing.T) {
	handler := NewHandler(Options{
		Audit: audit.Options{Root: fixtureRoot("example-bad")},
		Addr:  DefaultAddr,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var report audit.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "critical" {
		t.Fatalf("status = %s, want critical", report.Status)
	}
}

func TestAuditHandlerUsesGenericErrors(t *testing.T) {
	handler := NewHandler(Options{
		Audit: audit.Options{Root: filepath.Join("missing", "root")},
		Addr:  DefaultAddr,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["error"] != "local audit failed" {
		t.Fatalf("error = %q", got["error"])
	}
	if strings.Contains(rec.Body.String(), "missing") {
		t.Fatalf("response exposed raw path: %s", rec.Body.String())
	}
}

func TestUnsafePublicBindRefusalLogic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"0.0.0.0:8787", true},
		{"[::]:8787", true},
		{":8787", true},
		{"127.0.0.1:8787", false},
		{"localhost:8787", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := UnsafePublicBind(tt.addr); got != tt.want {
				t.Fatalf("UnsafePublicBind(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func fixtureRoot(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

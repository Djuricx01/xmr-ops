package output

import (
	"bytes"
	"testing"

	"xmr-ops/internal/audit"
)

func TestJSONOutputStability(t *testing.T) {
	report := audit.Report{
		Status: "warn",
		Root:   "/tmp/xmr",
		Strict: false,
		Findings: []audit.Finding{
			{
				CheckID:  "webhook_auth",
				Severity: audit.SeverityWarn,
				Title:    "webhook authentication or transport needs review",
				Evidence: []audit.Evidence{
					{File: ".env", Line: 2, Text: "PAYMENT_WEBHOOK=http://example.local/pay"},
				},
				File:           ".env",
				Line:           2,
				Recommendation: "Use HTTPS and a reviewed webhook secret or signature check.",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, report); err != nil {
		t.Fatal(err)
	}

	want := "{\n  \"status\": \"warn\",\n  \"root\": \"/tmp/xmr\",\n  \"strict\": false,\n  \"findings\": [\n    {\n      \"check_id\": \"webhook_auth\",\n      \"severity\": \"warn\",\n      \"title\": \"webhook authentication or transport needs review\",\n      \"evidence\": [\n        {\n          \"file\": \".env\",\n          \"line\": 2,\n          \"text\": \"PAYMENT_WEBHOOK=http://example.local/pay\"\n        }\n      ],\n      \"file\": \".env\",\n      \"line\": 2,\n      \"recommendation\": \"Use HTTPS and a reviewed webhook secret or signature check.\"\n    }\n  ]\n}\n"
	if buf.String() != want {
		t.Fatalf("json output changed:\n%s", buf.String())
	}
}

func TestExitCodeBehavior(t *testing.T) {
	tests := []struct {
		name   string
		report audit.Report
		strict bool
		want   int
	}{
		{
			name:   "pass and review",
			report: reportWith(audit.SeverityPass, audit.SeverityReview),
			strict: false,
			want:   0,
		},
		{
			name:   "warn",
			report: reportWith(audit.SeverityWarn),
			strict: false,
			want:   1,
		},
		{
			name:   "strict review",
			report: reportWith(audit.SeverityReview),
			strict: true,
			want:   1,
		},
		{
			name:   "critical",
			report: reportWith(audit.SeverityWarn, audit.SeverityCritical),
			strict: false,
			want:   2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.report, tt.strict); got != tt.want {
				t.Fatalf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func reportWith(severities ...audit.Severity) audit.Report {
	findings := make([]audit.Finding, 0, len(severities))
	for _, severity := range severities {
		findings = append(findings, audit.Finding{Severity: severity})
	}
	return audit.Report{Findings: findings}
}

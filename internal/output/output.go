package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"xmr-ops/internal/audit"
)

func WriteText(w io.Writer, report audit.Report, noColor bool) error {
	for i, finding := range report.Findings {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		label := fmt.Sprintf("%-8s", severityLabel(finding.Severity))
		if !noColor {
			label = color(finding.Severity) + label + "\033[0m"
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", label, finding.Title); err != nil {
			return err
		}
		for _, ev := range finding.Evidence {
			if _, err := fmt.Fprintf(w, "  %s\n", evidenceLine(ev)); err != nil {
				return err
			}
		}
	}
	return nil
}

func WriteJSON(w io.Writer, report audit.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

func ExitCode(report audit.Report, strict bool) int {
	warn := false
	for _, finding := range report.Findings {
		switch finding.Severity {
		case audit.SeverityCritical:
			return 2
		case audit.SeverityWarn:
			warn = true
		case audit.SeverityReview:
			if strict {
				warn = true
			}
		}
	}
	if warn {
		return 1
	}
	return 0
}

func severityLabel(sev audit.Severity) string {
	return strings.ToUpper(string(sev))
}

func color(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return "\033[31m"
	case audit.SeverityWarn:
		return "\033[33m"
	case audit.SeverityPass:
		return "\033[32m"
	default:
		return "\033[90m"
	}
}

func evidenceLine(ev audit.Evidence) string {
	switch {
	case ev.File != "" && ev.Line > 0:
		return fmt.Sprintf("%s:%d: %s", ev.File, ev.Line, ev.Text)
	case ev.File != "":
		if ev.Text == "" {
			return ev.File
		}
		return fmt.Sprintf("%s: %s", ev.File, ev.Text)
	default:
		return ev.Text
	}
}

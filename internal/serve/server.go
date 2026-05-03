package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"xmr-ops/internal/audit"
)

const DefaultAddr = "127.0.0.1:8787"

type Options struct {
	Audit            audit.Options
	Addr             string
	UnsafePublicBind bool
}

type healthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Root    string `json:"root"`
	Time    string `json:"time"`
}

type pageData struct {
	Version     string
	Root        string
	Status      string
	Counts      map[string]int
	Findings    []audit.Finding
	Config      audit.Config
	Node        audit.LocalStatus
	Wallet      audit.LocalStatus
	Privacy     audit.Finding
	Backup      audit.Finding
	UnsafeBind  bool
	GeneratedAt string
}

func Run(ctx context.Context, opts Options, out io.Writer) error {
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if UnsafePublicBind(opts.Addr) && !opts.UnsafePublicBind {
		return fmt.Errorf("refusing to bind %s without --unsafe-public-bind", opts.Addr)
	}
	if _, err := audit.Discover(opts.Audit); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	if opts.UnsafePublicBind {
		fmt.Fprintln(out, "WARNING: unsafe public bind requested; the v0 console has no authentication")
	}
	fmt.Fprintf(out, "xmr-ops console listening on http://%s\n", ln.Addr().String())

	srv := &http.Server{
		Handler:           NewHandler(opts),
		ReadHeaderTimeout: 5 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		case <-done:
		}
	}()

	err = srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func NewHandler(opts Options) http.Handler {
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !getOnly(w, r) {
			return
		}
		renderIndex(w, r, opts)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		cfg, err := audit.Discover(opts.Audit)
		if err != nil {
			writeError(w, "config discovery failed")
			return
		}
		writeJSON(w, healthResponse{
			OK:      true,
			Version: audit.Version,
			Root:    cfg.Root,
			Time:    time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		report, err := audit.Run(r.Context(), opts.Audit)
		if err != nil {
			writeError(w, "local audit failed")
			return
		}
		writeJSON(w, report)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		cfg, err := audit.Discover(opts.Audit)
		if err != nil {
			writeError(w, "config discovery failed")
			return
		}
		writeJSON(w, cfg)
	})
	mux.HandleFunc("/api/node/status", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		status, err := audit.NodeStatus(r.Context(), opts.Audit)
		if err != nil {
			writeError(w, "node status failed")
			return
		}
		writeJSON(w, status)
	})
	mux.HandleFunc("/api/wallet/status", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		status, err := audit.WalletStatus(opts.Audit)
		if err != nil {
			writeError(w, "wallet status failed")
			return
		}
		writeJSON(w, status)
	})
	return mux
}

func UnsafePublicBind(addr string) bool {
	return audit.PublicBindAddr(addr)
}

func renderIndex(w http.ResponseWriter, r *http.Request, opts Options) {
	report, err := audit.Run(r.Context(), opts.Audit)
	if err != nil {
		writeError(w, "local audit failed")
		return
	}
	cfg, err := audit.Discover(opts.Audit)
	if err != nil {
		writeError(w, "config discovery failed")
		return
	}
	node, err := audit.NodeStatus(r.Context(), opts.Audit)
	if err != nil {
		writeError(w, "node status failed")
		return
	}
	wallet, err := audit.WalletStatus(opts.Audit)
	if err != nil {
		writeError(w, "wallet status failed")
		return
	}

	data := pageData{
		Version:     audit.Version,
		Root:        report.Root,
		Status:      report.Status,
		Counts:      countFindings(report.Findings),
		Findings:    report.Findings,
		Config:      cfg,
		Node:        node,
		Wallet:      wallet,
		Privacy:     findByCheck(report.Findings, "tor_isolation"),
		Backup:      findByCheck(report.Findings, "backup_signal"),
		UnsafeBind:  opts.UnsafePublicBind && UnsafePublicBind(opts.Addr),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(w, data); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func countFindings(findings []audit.Finding) map[string]int {
	counts := map[string]int{
		string(audit.SeverityCritical): 0,
		string(audit.SeverityWarn):     0,
		string(audit.SeverityReview):   0,
		string(audit.SeverityPass):     0,
	}
	for _, finding := range findings {
		counts[string(finding.Severity)]++
	}
	return counts
}

func findByCheck(findings []audit.Finding, checkID string) audit.Finding {
	for _, finding := range findings {
		if finding.CheckID == checkID {
			return finding
		}
	}
	return audit.Finding{Severity: audit.SeverityReview, Title: "not detected"}
}

func joinPaths(paths []string) string {
	if len(paths) == 0 {
		return "not detected"
	}
	return strings.Join(paths, ", ")
}

var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"upper": func(v any) string { return strings.ToUpper(fmt.Sprint(v)) },
	"paths": joinPaths,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>xmr-ops</title>
<style>
:root {
  color-scheme: dark;
  --bg: #101214;
  --panel: #171b1f;
  --line: #2a3036;
  --text: #e7ecef;
  --muted: #9aa5ad;
  --critical: #ff5c5c;
  --warn: #f3b84b;
  --review: #9aa5ad;
  --pass: #70d17b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
main {
  width: min(1120px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 40px;
}
header {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
  border-bottom: 1px solid var(--line);
  padding-bottom: 18px;
}
h1, h2, h3, p { margin: 0; }
h1 { font-size: 22px; font-weight: 650; letter-spacing: 0; }
h2 { font-size: 15px; font-weight: 650; margin-bottom: 12px; }
h3 { font-size: 13px; font-weight: 650; color: var(--muted); margin-bottom: 6px; }
.muted { color: var(--muted); }
.status {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  border: 1px solid var(--line);
  padding: 4px 10px;
  font-weight: 650;
  text-transform: uppercase;
}
.critical { color: var(--critical); }
.warn { color: var(--warn); }
.review { color: var(--review); }
.pass { color: var(--pass); }
.grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin: 18px 0;
}
.metric, section {
  border: 1px solid var(--line);
  background: var(--panel);
}
.metric { padding: 12px; min-height: 72px; }
.metric strong { display: block; font-size: 24px; line-height: 1.1; margin-top: 4px; }
section { padding: 16px; margin-top: 14px; }
.split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
.kv {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: 8px 12px;
  color: var(--muted);
}
.kv div:nth-child(even) { color: var(--text); overflow-wrap: anywhere; }
.finding {
  border-top: 1px solid var(--line);
  padding: 12px 0;
}
.finding:first-child { border-top: 0; padding-top: 0; }
.finding:last-child { padding-bottom: 0; }
.finding-title {
  display: flex;
  gap: 10px;
  align-items: baseline;
}
.sev {
  width: 72px;
  flex: 0 0 72px;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
code {
  color: #d4dde3;
  overflow-wrap: anywhere;
}
ul {
  margin: 8px 0 0;
  padding-left: 18px;
  color: var(--muted);
}
.warning {
  border: 1px solid var(--warn);
  color: var(--warn);
  padding: 10px 12px;
  margin-top: 14px;
}
@media (max-width: 780px) {
  header, .split { grid-template-columns: 1fr; display: grid; }
  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .kv { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>xmr-ops</h1>
      <p class="muted">{{.Root}}</p>
    </div>
    <div class="status {{.Status}}">{{.Status}}</div>
  </header>
  {{if .UnsafeBind}}<div class="warning">Unsafe public bind is enabled. The v0 console has no authentication.</div>{{end}}
  <div class="grid">
    <div class="metric"><span class="muted">critical</span><strong class="critical">{{index .Counts "critical"}}</strong></div>
    <div class="metric"><span class="muted">warn</span><strong class="warn">{{index .Counts "warn"}}</strong></div>
    <div class="metric"><span class="muted">review</span><strong class="review">{{index .Counts "review"}}</strong></div>
    <div class="metric"><span class="muted">pass</span><strong class="pass">{{index .Counts "pass"}}</strong></div>
  </div>
  <div class="split">
    <section>
      <h2>Local Status</h2>
      <div class="kv">
        <div>monerod</div><div><span class="{{.Node.Severity}}">{{upper .Node.Severity}}</span> {{.Node.Summary}}</div>
        <div>wallet-rpc</div><div><span class="{{.Wallet.Severity}}">{{upper .Wallet.Severity}}</span> {{.Wallet.Summary}}</div>
        <div>privacy</div><div><span class="{{.Privacy.Severity}}">{{upper .Privacy.Severity}}</span> {{.Privacy.Title}}</div>
        <div>backup</div><div><span class="{{.Backup.Severity}}">{{upper .Backup.Severity}}</span> {{.Backup.Title}}</div>
      </div>
    </section>
    <section>
      <h2>Config Paths</h2>
      <div class="kv">
        <div>compose</div><div>{{paths .Config.ComposeFiles}}</div>
        <div>env</div><div>{{paths .Config.EnvFiles}}</div>
        <div>proxy</div><div>{{paths .Config.ProxyConfigFiles}}</div>
        <div>wallet dir</div><div>{{if .Config.WalletDir}}{{.Config.WalletDir}}{{else}}not set{{end}}</div>
      </div>
    </section>
  </div>
  <section>
    <h2>Audit</h2>
    {{range .Findings}}
      <div class="finding">
        <div class="finding-title"><span class="sev {{.Severity}}">{{upper .Severity}}</span><strong>{{.Title}}</strong></div>
        {{if .Evidence}}
          <ul>
          {{range .Evidence}}
            <li>{{if .File}}<code>{{.File}}{{if .Line}}:{{.Line}}{{end}}</code>: {{end}}{{.Text}}</li>
          {{end}}
          </ul>
        {{end}}
      </div>
    {{end}}
  </section>
  <p class="muted" style="margin-top:14px">version {{.Version}} · {{.GeneratedAt}}</p>
</main>
</body>
</html>`))

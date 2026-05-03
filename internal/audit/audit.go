package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0-dev"
const MinimumMonerodVersion = "0.18.3.4"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarn     Severity = "warn"
	SeverityReview   Severity = "review"
	SeverityPass     Severity = "pass"
)

type Options struct {
	Root       string
	Compose    string
	Env        string
	WalletDir  string
	Strict     bool
	NoColor    bool
	JSONOutput bool
}

type Evidence struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type Finding struct {
	CheckID        string     `json:"check_id"`
	Severity       Severity   `json:"severity"`
	Title          string     `json:"title"`
	Evidence       []Evidence `json:"evidence"`
	File           string     `json:"file"`
	Line           int        `json:"line"`
	Recommendation string     `json:"recommendation"`
}

type Report struct {
	Status   string    `json:"status"`
	Root     string    `json:"root"`
	Strict   bool      `json:"strict"`
	Findings []Finding `json:"findings"`
}

type Config struct {
	Root             string   `json:"root"`
	ComposeFiles     []string `json:"compose_files"`
	EnvFiles         []string `json:"env_files"`
	ProxyConfigFiles []string `json:"proxy_config_files"`
	WalletDir        string   `json:"wallet_dir,omitempty"`
}

type LocalStatus struct {
	Severity Severity   `json:"severity"`
	Summary  string     `json:"summary"`
	Evidence []Evidence `json:"evidence"`
	Details  []string   `json:"details,omitempty"`
}

type InvalidPathError struct {
	Path string
	Err  error
}

func (e *InvalidPathError) Error() string {
	if e.Path == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e *InvalidPathError) Unwrap() error {
	return e.Err
}

type pathRef struct {
	Abs      string
	Display  string
	Explicit bool
}

type textFile struct {
	pathRef
	Lines  []string
	Mode   os.FileMode
	ModeOK bool
}

type state struct {
	Config      Config
	Compose     []textFile
	Env         []textFile
	Proxy       []textFile
	ConfigFiles []textFile
	WalletFiles []pathRef
	AllPaths    []pathRef
}

var defaultComposeNames = []string{
	"docker-compose.yml",
	"docker-compose.yaml",
	"compose.yml",
	"compose.yaml",
}

var defaultEnvNames = []string{
	".env",
	".env.local",
	"moneropay.env",
	"wallet-rpc.env",
}

var proxyDirs = []string{
	"nginx",
	"caddy",
	"traefik",
	"conf",
	"config",
}

var redactionNameRe = regexp.MustCompile(`(?i)\b([A-Z0-9_.-]*(SECRET|TOKEN|PASSWORD|PASS|KEY|AUTH|SEED|MNEMONIC)[A-Z0-9_.-]*\s*[:=]\s*)(.+)$`)
var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+(?:\.\d+)?`)
var urlRe = regexp.MustCompile(`https?://[^\s'"<>]+`)
var backupTarRe = regexp.MustCompile(`(?i)(^|[^a-z0-9_-])tar([^a-z0-9_-]|$)`)

func Run(ctx context.Context, opts Options) (Report, error) {
	st, err := buildState(opts)
	if err != nil {
		return Report{}, err
	}

	findings := []Finding{
		checkWalletRPCNoAuth(st),
		checkUnsafeRPCBind(st),
		checkWeakFilePermissions(st),
		checkMonerodVersion(ctx, st),
		checkFirewallSignal(st),
		checkReverseProxyRisk(st),
		checkTorIsolation(st),
		checkWebhookAuth(st),
		checkBackupSignal(st),
		checkSecretLeakSignal(st),
		checkDockerSocketRisk(st),
		checkContainerPrivilegeRisk(st),
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	return Report{
		Status:   reportStatus(findings),
		Root:     st.Config.Root,
		Strict:   opts.Strict,
		Findings: findings,
	}, nil
}

func Discover(opts Options) (Config, error) {
	st, err := buildState(Options{
		Root:      opts.Root,
		Compose:   opts.Compose,
		Env:       opts.Env,
		WalletDir: opts.WalletDir,
	})
	if err != nil {
		return Config{}, err
	}
	return st.Config, nil
}

func NodeStatus(ctx context.Context, opts Options) (LocalStatus, error) {
	st, err := buildState(opts)
	if err != nil {
		return LocalStatus{}, err
	}

	ev := []Evidence{}
	details := []string{}

	imageEvidence, versions, unpinned := composeImageVersions(st)
	ev = append(ev, imageEvidence...)
	for _, v := range versions {
		if compareVersions(v, MinimumMonerodVersion) < 0 {
			return LocalStatus{
				Severity: SeverityWarn,
				Summary:  "compose image tag is below local baseline " + MinimumMonerodVersion,
				Evidence: ev,
				Details:  details,
			}, nil
		}
	}
	if unpinned || len(ev) > 0 && len(versions) == 0 {
		return LocalStatus{
			Severity: SeverityReview,
			Summary:  "monerod image tag needs manual review",
			Evidence: ev,
			Details:  details,
		}, nil
	}
	if len(versions) > 0 {
		return LocalStatus{
			Severity: SeverityPass,
			Summary:  "compose image tag meets local baseline " + MinimumMonerodVersion,
			Evidence: ev,
			Details:  details,
		}, nil
	}

	if path, ok := monerodPath(); ok {
		details = append(details, "monerod in PATH")
		if v, raw, ok := monerodVersionFromPath(ctx, path); ok {
			ev = append(ev, Evidence{Text: strings.TrimSpace(raw)})
			if compareVersions(v, MinimumMonerodVersion) < 0 {
				return LocalStatus{
					Severity: SeverityWarn,
					Summary:  "monerod is below local baseline " + MinimumMonerodVersion,
					Evidence: ev,
					Details:  details,
				}, nil
			}
			return LocalStatus{
				Severity: SeverityPass,
				Summary:  "monerod meets local baseline " + MinimumMonerodVersion,
				Evidence: ev,
				Details:  details,
			}, nil
		}
	}

	bind := findPublicBindEvidence(st, []string{"18081", "18089", "18083"})
	if len(bind) > 0 {
		return LocalStatus{
			Severity: SeverityReview,
			Summary:  "monerod RPC bind detected; manual review",
			Evidence: bind,
			Details:  details,
		}, nil
	}

	return LocalStatus{
		Severity: SeverityReview,
		Summary:  "monerod status not detected",
		Details:  details,
	}, nil
}

func WalletStatus(opts Options) (LocalStatus, error) {
	st, err := buildState(opts)
	if err != nil {
		return LocalStatus{}, err
	}

	walletDetected, walletEv := walletRPCDetected(st)
	if !walletDetected {
		return LocalStatus{
			Severity: SeverityReview,
			Summary:  "wallet-rpc not detected",
			Evidence: walletEv,
		}, nil
	}

	publicEv := walletPublicExposure(st)
	disabledEv := rpcLoginDisabled(st)
	localEv := walletLocalhostBind(st)

	if len(publicEv) > 0 && len(disabledEv) > 0 {
		return LocalStatus{
			Severity: SeverityCritical,
			Summary:  "wallet-rpc may be exposed without authentication",
			Evidence: append(publicEv, disabledEv...),
		}, nil
	}
	if len(publicEv) > 0 {
		return LocalStatus{
			Severity: SeverityWarn,
			Summary:  "wallet-rpc appears exposed; authentication not detected",
			Evidence: publicEv,
		}, nil
	}
	if len(localEv) > 0 && len(disabledEv) == 0 {
		return LocalStatus{
			Severity: SeverityPass,
			Summary:  "wallet-rpc appears locally bound with login not disabled",
			Evidence: localEv,
		}, nil
	}

	return LocalStatus{
		Severity: SeverityReview,
		Summary:  "wallet-rpc posture is unclear",
		Evidence: walletEv,
	}, nil
}

func RedactText(text string) string {
	trimmed := strings.TrimSpace(text)
	if redactionNameRe.MatchString(trimmed) {
		return redactionNameRe.ReplaceAllString(trimmed, `${1}<redacted>`)
	}
	lower := strings.ToLower(trimmed)
	phrases := []string{
		"private spend key",
		"private view key",
		"wallet password",
		"rpc password",
		"api secret",
		"webhook secret",
		"mnemonic",
		"seed phrase",
	}
	for _, phrase := range phrases {
		if strings.Contains(lower, phrase) {
			if idx := strings.IndexAny(trimmed, "=:"); idx >= 0 {
				return strings.TrimSpace(trimmed[:idx+1]) + " <redacted>"
			}
			return "<redacted>"
		}
	}
	return trimmed
}

func buildState(opts Options) (state, error) {
	root, err := resolveRoot(opts.Root)
	if err != nil {
		return state{}, err
	}

	composeRefs, err := discoverCompose(root, opts.Compose)
	if err != nil {
		return state{}, err
	}
	envRefs, err := discoverEnv(root, opts.Env)
	if err != nil {
		return state{}, err
	}
	proxyRefs := discoverProxy(root)
	allRefs := discoverAll(root)
	walletDir, walletRefs, err := discoverWalletFiles(root, opts.WalletDir, allRefs)
	if err != nil {
		return state{}, err
	}

	composeFiles, err := loadTextFiles(composeRefs)
	if err != nil {
		return state{}, err
	}
	envFiles, err := loadTextFiles(envRefs)
	if err != nil {
		return state{}, err
	}
	proxyFiles, err := loadTextFiles(proxyRefs)
	if err != nil {
		return state{}, err
	}

	configFiles := make([]textFile, 0, len(composeFiles)+len(envFiles)+len(proxyFiles))
	configFiles = append(configFiles, composeFiles...)
	configFiles = append(configFiles, envFiles...)
	configFiles = append(configFiles, proxyFiles...)

	cfg := Config{
		Root:             root,
		ComposeFiles:     displays(composeRefs),
		EnvFiles:         displays(envRefs),
		ProxyConfigFiles: displays(proxyRefs),
		WalletDir:        walletDir,
	}

	return state{
		Config:      cfg,
		Compose:     composeFiles,
		Env:         envFiles,
		Proxy:       proxyFiles,
		ConfigFiles: configFiles,
		WalletFiles: walletRefs,
		AllPaths:    allRefs,
	}, nil
}

func resolveRoot(root string) (string, error) {
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", &InvalidPathError{Err: err}
		}
		root = wd
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", &InvalidPathError{Path: root, Err: err}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", &InvalidPathError{Path: root, Err: err}
	}
	if !info.IsDir() {
		return "", &InvalidPathError{Path: root, Err: errors.New("not a directory")}
	}
	return filepath.Clean(abs), nil
}

func discoverCompose(root, explicit string) ([]pathRef, error) {
	if explicit != "" {
		ref, err := explicitFile(root, explicit)
		if err != nil {
			return nil, err
		}
		return []pathRef{ref}, nil
	}
	return defaultFiles(root, defaultComposeNames), nil
}

func discoverEnv(root, explicit string) ([]pathRef, error) {
	if explicit != "" {
		ref, err := explicitFile(root, explicit)
		if err != nil {
			return nil, err
		}
		return []pathRef{ref}, nil
	}
	return defaultFiles(root, defaultEnvNames), nil
}

func discoverProxy(root string) []pathRef {
	var refs []pathRef
	for _, dir := range proxyDirs {
		base := filepath.Join(root, dir)
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				refs = append(refs, newRef(root, path, false))
			}
			return nil
		})
	}
	sortRefs(refs)
	return refs
}

func discoverAll(root string) []pathRef {
	var refs []pathRef
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case ".git", "node_modules", "vendor":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			refs = append(refs, newRef(root, path, false))
		}
		return nil
	})
	sortRefs(refs)
	return refs
}

func discoverWalletFiles(root, explicit string, allRefs []pathRef) (string, []pathRef, error) {
	var refs []pathRef
	walletDir := ""
	seen := map[string]bool{}

	if explicit != "" {
		dirRef, err := explicitDir(root, explicit)
		if err != nil {
			return "", nil, err
		}
		walletDir = dirRef.Display
		filepath.WalkDir(dirRef.Abs, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				ref := newRef(root, path, filepath.IsAbs(explicit))
				if !seen[ref.Abs] {
					refs = append(refs, ref)
					seen[ref.Abs] = true
				}
			}
			return nil
		})
	}

	for _, ref := range allRefs {
		if walletLookingPath(ref.Abs) && !seen[ref.Abs] {
			refs = append(refs, ref)
			seen[ref.Abs] = true
		}
	}

	sortRefs(refs)
	return walletDir, refs, nil
}

func defaultFiles(root string, names []string) []pathRef {
	var refs []pathRef
	for _, name := range names {
		path := filepath.Join(root, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			refs = append(refs, newRef(root, path, false))
		}
	}
	return refs
}

func explicitFile(root, raw string) (pathRef, error) {
	abs, err := resolveExplicit(root, raw)
	if err != nil {
		return pathRef{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return pathRef{}, &InvalidPathError{Path: raw, Err: err}
	}
	if !info.Mode().IsRegular() {
		return pathRef{}, &InvalidPathError{Path: raw, Err: errors.New("not a regular file")}
	}
	return newRef(root, abs, true), nil
}

func explicitDir(root, raw string) (pathRef, error) {
	abs, err := resolveExplicit(root, raw)
	if err != nil {
		return pathRef{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return pathRef{}, &InvalidPathError{Path: raw, Err: err}
	}
	if !info.IsDir() {
		return pathRef{}, &InvalidPathError{Path: raw, Err: errors.New("not a directory")}
	}
	return newRef(root, abs, true), nil
}

func resolveExplicit(root, raw string) (string, error) {
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw), nil
	}
	abs := filepath.Clean(filepath.Join(root, raw))
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", &InvalidPathError{Path: raw, Err: errors.New("relative path escapes root")}
	}
	return abs, nil
}

func newRef(root, abs string, explicit bool) pathRef {
	abs = filepath.Clean(abs)
	return pathRef{
		Abs:      abs,
		Display:  displayPath(root, abs),
		Explicit: explicit,
	}
}

func displayPath(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if rel == "." {
			return "."
		}
		return filepath.ToSlash(rel)
	}
	return abs
}

func sortRefs(refs []pathRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		return refs[i].Display < refs[j].Display
	})
}

func displays(refs []pathRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.Display)
	}
	return out
}

func loadTextFiles(refs []pathRef) ([]textFile, error) {
	files := make([]textFile, 0, len(refs))
	for _, ref := range refs {
		tf, err := loadTextFile(ref)
		if err != nil {
			if ref.Explicit {
				return nil, &InvalidPathError{Path: ref.Display, Err: err}
			}
			continue
		}
		files = append(files, tf)
	}
	return files, nil
}

func loadTextFile(ref pathRef) (textFile, error) {
	info, err := os.Stat(ref.Abs)
	if err != nil {
		return textFile{}, err
	}
	f, err := os.Open(ref.Abs)
	if err != nil {
		return textFile{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return textFile{}, err
	}

	return textFile{
		pathRef: ref,
		Lines:   lines,
		Mode:    info.Mode().Perm(),
		ModeOK:  true,
	}, nil
}

func checkWalletRPCNoAuth(st state) Finding {
	walletDetected, detectEv := walletRPCDetected(st)
	publicEv := walletPublicExposure(st)
	disabledEv := rpcLoginDisabled(st)
	localEv := walletLocalhostBind(st)

	if len(publicEv) > 0 && len(disabledEv) > 0 {
		ev := append(copyEvidence(publicEv), disabledEv...)
		return finding("wallet_rpc_no_auth", SeverityCritical, "wallet-rpc may be exposed without authentication", ev, "Do not expose wallet-rpc publicly with disabled login.")
	}
	if len(publicEv) > 0 {
		return finding("wallet_rpc_no_auth", SeverityWarn, "wallet-rpc appears exposed; authentication not detected", publicEv, "Bind wallet-rpc to localhost or require RPC login behind a trusted local path.")
	}
	if walletDetected && len(localEv) > 0 && len(disabledEv) == 0 {
		return finding("wallet_rpc_no_auth", SeverityPass, "wallet-rpc appears locally bound with login not disabled", localEv, "Keep wallet-rpc off public interfaces.")
	}
	return finding("wallet_rpc_no_auth", SeverityReview, "wallet-rpc not detected", detectEv, "Manual review if wallet-rpc is configured outside the scanned files.")
}

func checkUnsafeRPCBind(st state) Finding {
	walletEv := walletPublicExposure(st)
	if len(walletEv) > 0 {
		return finding("unsafe_rpc_bind", SeverityCritical, "wallet-rpc appears publicly bound or published", walletEv, "Bind wallet-rpc to localhost unless there is a reviewed local-only boundary.")
	}

	monerodEv := monerodPublicExposure(st)
	if len(monerodEv) > 0 {
		return finding("unsafe_rpc_bind", SeverityWarn, "monerod RPC appears publicly bound or published", monerodEv, "Prefer restricted RPC and a reviewed network boundary for public monerod RPC.")
	}

	localEv := localhostBindEvidence(st)
	if len(localEv) > 0 {
		return finding("unsafe_rpc_bind", SeverityPass, "RPC bind appears local", localEv, "Keep public exposure intentional and reviewed.")
	}

	return finding("unsafe_rpc_bind", SeverityReview, "RPC bind not detected", nil, "Manual review if RPC is configured outside compose, env, or proxy files.")
}

type permKind int

const (
	permEnv permKind = iota
	permWallet
	permConfig
)

func checkWeakFilePermissions(st state) Finding {
	targets := permissionTargets(st)
	if runtime.GOOS == "windows" {
		ev := []Evidence{{Text: "POSIX permission checks are manual review on Windows"}}
		return finding("weak_file_permissions", SeverityReview, "file permissions need manual review on Windows", ev, "Review ACLs for env, wallet, and config files.")
	}
	if len(targets) == 0 {
		return finding("weak_file_permissions", SeverityReview, "no env, wallet, or config files found for permission checks", nil, "Manual review if sensitive files live outside the scanned root.")
	}

	var warnEv []Evidence
	var passEv []Evidence
	var reviewEv []Evidence
	for _, target := range targets {
		ev := Evidence{File: target.ref.Display, Text: target.modeText()}
		if target.modeOK {
			ev.Line = 0
		}
		severity := classifyMode(target.kind, target.mode, runtime.GOOS == "windows", target.modeOK)
		switch severity {
		case SeverityWarn:
			warnEv = append(warnEv, ev)
		case SeverityReview:
			reviewEv = append(reviewEv, ev)
		default:
			passEv = append(passEv, ev)
		}
	}

	if len(warnEv) > 0 {
		return finding("weak_file_permissions", SeverityWarn, "file permissions look too broad", warnEv, "Restrict env files and wallet-looking files before exposing services.")
	}
	if len(reviewEv) > 0 {
		return finding("weak_file_permissions", SeverityReview, "file permissions could not be determined", reviewEv, "Manual review of file permissions is needed.")
	}
	return finding("weak_file_permissions", SeverityPass, "file permissions look restrictive", passEv, "Keep secret-bearing files restricted to the service user.")
}

type permTarget struct {
	ref    pathRef
	kind   permKind
	mode   os.FileMode
	modeOK bool
}

func (p permTarget) modeText() string {
	if !p.modeOK {
		return "permissions not detected"
	}
	return fmt.Sprintf("0%o", p.mode.Perm())
}

func permissionTargets(st state) []permTarget {
	seen := map[string]bool{}
	var targets []permTarget
	for _, file := range st.Env {
		targets = append(targets, permTarget{ref: file.pathRef, kind: permEnv, mode: file.Mode, modeOK: file.ModeOK})
		seen[file.Abs] = true
	}
	for _, file := range st.Compose {
		if !seen[file.Abs] {
			targets = append(targets, permTarget{ref: file.pathRef, kind: permConfig, mode: file.Mode, modeOK: file.ModeOK})
			seen[file.Abs] = true
		}
	}
	for _, file := range st.Proxy {
		if !seen[file.Abs] {
			targets = append(targets, permTarget{ref: file.pathRef, kind: permConfig, mode: file.Mode, modeOK: file.ModeOK})
			seen[file.Abs] = true
		}
	}
	for _, ref := range st.WalletFiles {
		if seen[ref.Abs] {
			continue
		}
		info, err := os.Stat(ref.Abs)
		if err != nil {
			targets = append(targets, permTarget{ref: ref, kind: permWallet, modeOK: false})
			seen[ref.Abs] = true
			continue
		}
		targets = append(targets, permTarget{ref: ref, kind: permWallet, mode: info.Mode().Perm(), modeOK: true})
		seen[ref.Abs] = true
	}
	return targets
}

func classifyMode(kind permKind, mode os.FileMode, windows bool, modeOK bool) Severity {
	if windows {
		return SeverityReview
	}
	if !modeOK {
		return SeverityReview
	}
	switch kind {
	case permEnv:
		if mode.Perm()&0004 != 0 {
			return SeverityWarn
		}
	case permWallet:
		if mode.Perm()&0077 != 0 {
			return SeverityWarn
		}
	default:
		if mode.Perm()&0004 != 0 {
			return SeverityWarn
		}
	}
	return SeverityPass
}

func checkMonerodVersion(ctx context.Context, st state) Finding {
	ev, versions, unpinned := composeImageVersions(st)
	for _, v := range versions {
		if compareVersions(v, MinimumMonerodVersion) < 0 {
			return finding("monerod_version", SeverityWarn, "monerod image tag is below local baseline "+MinimumMonerodVersion, ev, "Review the local baseline before deciding whether to upgrade.")
		}
	}
	if unpinned || len(ev) > 0 && len(versions) == 0 {
		return finding("monerod_version", SeverityReview, "monerod image tag needs manual review", ev, "Pin image tags to a reviewed Monero release when practical.")
	}
	if len(versions) > 0 {
		return finding("monerod_version", SeverityPass, "monerod image tag meets local baseline "+MinimumMonerodVersion, ev, "Keep compose image tags pinned and reviewed.")
	}

	if path, ok := monerodPath(); ok {
		if v, raw, ok := monerodVersionFromPath(ctx, path); ok {
			ev := []Evidence{{Text: strings.TrimSpace(raw)}}
			if compareVersions(v, MinimumMonerodVersion) < 0 {
				return finding("monerod_version", SeverityWarn, "monerod is below local baseline "+MinimumMonerodVersion, ev, "Review the local baseline before deciding whether to upgrade.")
			}
			return finding("monerod_version", SeverityPass, "monerod meets local baseline "+MinimumMonerodVersion, ev, "Keep the local baseline reviewed with release policy.")
		}
	}
	return finding("monerod_version", SeverityReview, "monerod version could not be determined", []Evidence{{Text: "monerod not found in PATH and no image tag found"}}, "Manual review if monerod is installed outside PATH or managed by another supervisor.")
}

func monerodPath() (string, bool) {
	path, err := exec.LookPath("monerod")
	return path, err == nil
}

func monerodVersionFromPath(ctx context.Context, path string) (string, string, bool) {
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, path, "--version").CombinedOutput()
	if err != nil {
		return "", string(out), false
	}
	v := versionRe.FindString(string(out))
	if v == "" {
		return "", string(out), false
	}
	return v, string(out), true
}

func composeImageVersions(st state) ([]Evidence, []string, bool) {
	var ev []Evidence
	var versions []string
	unpinned := false
	for _, file := range st.Compose {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, "image:") {
				continue
			}
			if !strings.Contains(lower, "monero") && !strings.Contains(lower, "monerod") && !strings.Contains(lower, "sethsimmons/simple-monerod") && !strings.Contains(lower, "ghcr.io/sethforprivacy/simple-monerod") {
				continue
			}
			ev = append(ev, evidence(file, i, line))
			image := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "image:"))
			tag := imageTag(image)
			if tag == "" || strings.EqualFold(tag, "latest") || strings.EqualFold(tag, "unstable") {
				unpinned = true
				continue
			}
			if v := versionRe.FindString(tag); v != "" {
				versions = append(versions, v)
			} else {
				unpinned = true
			}
		}
	}
	return ev, versions, unpinned
}

func imageTag(image string) string {
	image = strings.Trim(image, `"'`)
	if strings.Contains(image, "@sha256:") {
		return ""
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return ""
	}
	return image[lastColon+1:]
}

func compareVersions(a, b string) int {
	ap := versionParts(a)
	bp := versionParts(b)
	for i := 0; i < len(ap) || i < len(bp); i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func versionParts(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, _ := strconv.Atoi(part)
		out = append(out, n)
	}
	return out
}

func checkFirewallSignal(st state) Finding {
	publicEv := append(copyEvidence(walletPublicExposure(st)), monerodPublicExposure(st)...)
	signalEv := firewallSignalEvidence(st)

	if len(publicEv) > 0 && len(signalEv) == 0 {
		return finding("firewall_signal", SeverityWarn, "public RPC bind detected without firewall signal", publicEv, "Review network boundaries; this tool does not change firewall rules.")
	}
	if len(publicEv) > 0 {
		return finding("firewall_signal", SeverityReview, "firewall signal found near public bind", signalEv, "Manual review is required; firewall signal does not prove correct filtering.")
	}
	if len(st.ConfigFiles) > 0 {
		return finding("firewall_signal", SeverityPass, "no public RPC bind detected in scanned configs", nil, "Keep firewall policy reviewed outside this tool.")
	}
	return finding("firewall_signal", SeverityReview, "not enough local config to assess firewall posture", nil, "Manual review if services are managed outside the scanned root.")
}

func firewallSignalEvidence(st state) []Evidence {
	terms := []string{
		"ufw",
		"iptables",
		"nft",
		"nftables",
		"firewall-cmd",
		"security group",
		"allowlist",
		"denylist",
		"tailscale",
		"wireguard",
		"vpn",
		"sg-",
		"ingress",
	}
	var ev []Evidence
	for _, ref := range st.AllPaths {
		name := strings.ToLower(ref.Display)
		if containsAny(name, terms) {
			ev = append(ev, Evidence{File: ref.Display, Text: "firewall signal in file name"})
		}
	}
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			if containsAny(strings.ToLower(line), terms) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func checkReverseProxyRisk(st state) Finding {
	if len(st.Proxy) == 0 {
		return finding("reverse_proxy_risk", SeverityReview, "reverse proxy config not detected", nil, "Manual review if reverse proxy config lives outside common directories.")
	}

	var criticalEv []Evidence
	var warnEv []Evidence
	for _, file := range st.Proxy {
		authSignal := fileContainsAny(file, []string{
			"authorization",
			"x-signature",
			"x-webhook-signature",
			"hmac",
			"basic_auth",
			"basicauth",
			"forward_auth",
			"auth_request",
			"bearer",
			"token",
			"secret",
		})
		publicSignal := fileContainsAny(file, []string{
			"listen 80",
			"listen 443",
			":80",
			":443",
			"0.0.0.0",
			"server_name",
		})
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if (strings.Contains(lower, "proxy_pass") || strings.Contains(lower, "reverse_proxy")) && strings.Contains(lower, "18082") {
				if publicSignal {
					criticalEv = append(criticalEv, evidence(file, i, line))
				} else {
					warnEv = append(warnEv, evidence(file, i, line))
				}
			}
			if containsAny(lower, []string{"webhook", "callback", "admin", "wallet", "rpc"}) && !authSignal {
				warnEv = append(warnEv, evidence(file, i, line))
			}
			if strings.Contains(lower, "listen 80") || strings.Contains(lower, "http://") || strings.Contains(lower, "tls off") || strings.Contains(lower, "tls disabled") {
				warnEv = append(warnEv, evidence(file, i, line))
			}
		}
	}

	if len(criticalEv) > 0 {
		return finding("reverse_proxy_risk", SeverityCritical, "reverse proxy appears to expose wallet-rpc", uniqueEvidence(criticalEv), "Do not proxy wallet-rpc to public routes.")
	}
	if len(warnEv) > 0 {
		return finding("reverse_proxy_risk", SeverityWarn, "reverse proxy needs manual review", uniqueEvidence(warnEv), "Review public routes, TLS, and auth headers for webhook or admin paths.")
	}
	return finding("reverse_proxy_risk", SeverityPass, "reverse proxy risk not detected", nil, "Keep proxy routes narrow and reviewed.")
}

func checkTorIsolation(st state) Finding {
	var clearnetEv []Evidence
	var privacyEv []Evidence
	privacyTerms := []string{
		"tor",
		"torsocks",
		"socks5",
		"i2p",
		"hidden service",
		"onion",
		"tx-proxy",
		"tx_proxy",
		"anonymous-inbound",
	}
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if containsAny(lower, privacyTerms) || privacyProxySignal(lower) {
				privacyEv = append(privacyEv, evidence(file, i, line))
			}
			if containsAny(lower, []string{"remote-node", "remote_node", "daemon-address", "public rpc", "clearnet", "0.0.0.0:18082", "0.0.0.0:18081"}) {
				clearnetEv = append(clearnetEv, evidence(file, i, line))
			}
			if strings.Contains(lower, "http://") && containsAny(lower, []string{"18081", "18082", "node", "daemon", "rpc"}) {
				clearnetEv = append(clearnetEv, evidence(file, i, line))
			}
		}
	}

	if len(clearnetEv) > 0 && len(privacyEv) == 0 {
		return finding("tor_isolation", SeverityWarn, "privacy isolation signal not detected for clearnet RPC posture", clearnetEv, "Manual review of Tor/I2P or local-only routing may be appropriate.")
	}
	if len(clearnetEv) > 0 && len(privacyEv) > 0 {
		ev := append(copyEvidence(clearnetEv), privacyEv...)
		return finding("tor_isolation", SeverityReview, "privacy isolation signal found; manual review needed", uniqueEvidence(ev), "Presence of Tor/I2P terms does not prove isolation is correct.")
	}
	if len(privacyEv) > 0 {
		return finding("tor_isolation", SeverityReview, "privacy isolation signal detected", uniqueEvidence(privacyEv), "Presence of Tor/I2P/proxy terms does not prove isolation is correct.")
	}
	return finding("tor_isolation", SeverityReview, "privacy isolation signal not detected", nil, "Manual review if remote nodes or public RPC are configured elsewhere.")
}

func checkWebhookAuth(st state) Finding {
	webhookEv, secretEv, hasHTTP, hasHTTPS := webhookEvidence(st)
	if len(webhookEv) == 0 {
		return finding("webhook_auth", SeverityReview, "webhook URL not detected", nil, "Manual review if webhooks are configured outside scanned files.")
	}
	if hasHTTP || len(secretEv) == 0 {
		ev := append(copyEvidence(webhookEv), secretEv...)
		return finding("webhook_auth", SeverityWarn, "webhook authentication or transport needs review", uniqueEvidence(ev), "Use HTTPS and a reviewed webhook secret or signature check.")
	}
	if hasHTTPS {
		ev := append(copyEvidence(webhookEv), secretEv...)
		return finding("webhook_auth", SeverityPass, "webhook uses HTTPS with an auth signal", uniqueEvidence(ev), "Keep webhook secrets out of public-readable files.")
	}
	return finding("webhook_auth", SeverityReview, "webhook posture is unclear", webhookEv, "Manual review of webhook transport and authentication is needed.")
}

func webhookEvidence(st state) ([]Evidence, []Evidence, bool, bool) {
	urlNames := []string{"webhook", "callback", "hook", "notify", "notification"}
	secretNames := []string{
		"webhook_secret",
		"callback_secret",
		"moneropay_webhook_secret",
		"auth_token",
		"api_key",
		"signing_secret",
		"hmac_secret",
		"shared_secret",
		"callback_token",
	}
	var webhookEv []Evidence
	var secretEv []Evidence
	hasHTTP := false
	hasHTTPS := false
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if containsAny(lower, urlNames) && urlRe.MatchString(line) {
				webhookEv = append(webhookEv, evidence(file, i, line))
				for _, url := range urlRe.FindAllString(line, -1) {
					if strings.HasPrefix(strings.ToLower(url), "http://") {
						hasHTTP = true
					}
					if strings.HasPrefix(strings.ToLower(url), "https://") {
						hasHTTPS = true
					}
				}
			}
			if containsAny(lower, secretNames) {
				secretEv = append(secretEv, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(webhookEv), uniqueEvidence(secretEv), hasHTTP, hasHTTPS
}

func hasWebhookSecret(lines []string) bool {
	_, secretEv, _, _ := webhookEvidence(state{ConfigFiles: []textFile{{Lines: lines}}})
	return len(secretEv) > 0
}

func checkBackupSignal(st state) Finding {
	deployment := deploymentDetected(st)
	ev := backupEvidence(st)

	if deployment && len(ev) == 0 {
		return finding("backup_signal", SeverityWarn, "backup signal not detected for wallet/payment deployment", nil, "Manual review of backup and recovery is needed.")
	}
	if len(ev) > 0 {
		return finding("backup_signal", SeverityReview, "backup signal found; recovery not proven", uniqueEvidence(ev), "Verify restore procedures manually.")
	}
	return finding("backup_signal", SeverityReview, "wallet/payment deployment not detected for backup posture", nil, "Manual review if sensitive state is stored outside scanned files.")
}

func deploymentDetected(st state) bool {
	for _, file := range st.ConfigFiles {
		for _, line := range file.Lines {
			if containsAny(strings.ToLower(line), []string{"monero", "moneropay", "btcpay", "wallet-rpc", "18082", "18081"}) {
				return true
			}
		}
	}
	return len(st.WalletFiles) > 0
}

func backupEvidence(st state) []Evidence {
	terms := []string{
		"backup",
		"backups",
		"restic",
		"borg",
		"rclone",
		"dump",
		"snapshot",
		"wallet backup",
		"cron",
		"crontab",
		"systemd timer",
		"tar",
		"rsync",
	}
	var ev []Evidence
	for _, ref := range st.AllPaths {
		if backupSignalText(ref.Display, terms) {
			ev = append(ev, Evidence{File: ref.Display, Text: "backup signal in file name"})
		}
	}
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			if backupSignalText(line, terms) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func backupSignalText(text string, terms []string) bool {
	lower := strings.ToLower(text)
	for _, term := range terms {
		if term == "tar" {
			if backupTarRe.MatchString(lower) {
				return true
			}
			continue
		}
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func checkSecretLeakSignal(st state) Finding {
	var warnEv []Evidence
	var reviewEv []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			if !secretLooking(line) {
				continue
			}
			ev := evidence(file, i, line)
			if runtime.GOOS == "windows" || !file.ModeOK {
				reviewEv = append(reviewEv, ev)
				continue
			}
			if file.Mode.Perm()&0004 != 0 {
				warnEv = append(warnEv, ev)
			}
		}
	}
	if len(warnEv) > 0 {
		return finding("secret_leak_signal", SeverityWarn, "secret-looking values found in world-readable config", uniqueEvidence(warnEv), "Move secrets to restrictive local files and review exposure.")
	}
	if len(reviewEv) > 0 {
		return finding("secret_leak_signal", SeverityReview, "secret-looking values found; permissions need manual review", uniqueEvidence(reviewEv), "Review file ACLs and avoid public-readable secret files.")
	}
	return finding("secret_leak_signal", SeverityPass, "obvious secret leak signal not detected", nil, "Continue keeping secrets out of public-ish config.")
}

func secretLooking(line string) bool {
	lower := strings.ToLower(line)
	if !strings.ContainsAny(line, "=:") {
		return false
	}
	terms := []string{
		"seed phrase",
		"mnemonic",
		"private spend key",
		"private view key",
		"wallet password",
		"wallet_password",
		"rpc password",
		"rpc_password",
		"api secret",
		"api_secret",
		"webhook secret",
		"webhook_secret",
		"signing_secret",
		"hmac_secret",
		"shared_secret",
	}
	return containsAny(lower, terms) || redactionNameRe.MatchString(line)
}

func checkDockerSocketRisk(st state) Finding {
	if len(st.Compose) == 0 {
		return finding("docker_socket_risk", SeverityReview, "compose file not detected", nil, "Manual review if containers are managed outside compose.")
	}
	var ev []Evidence
	for _, file := range st.Compose {
		for i, line := range file.Lines {
			if strings.Contains(strings.ToLower(line), "docker.sock") {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	if len(ev) > 0 {
		return finding("docker_socket_risk", SeverityWarn, "docker socket is mounted", uniqueEvidence(ev), "Avoid mounting docker.sock into Monero or payment-facing containers.")
	}
	return finding("docker_socket_risk", SeverityPass, "docker socket mount not detected", nil, "Keep docker socket out of payment-facing containers.")
}

func checkContainerPrivilegeRisk(st state) Finding {
	if len(st.Compose) == 0 {
		return finding("container_privilege_risk", SeverityReview, "compose file not detected", nil, "Manual review if containers are managed outside compose.")
	}
	riskTerms := []string{"privileged: true", "network_mode: host", "cap_add", "pid: host"}
	var warnEv []Evidence
	var reviewEv []Evidence
	for _, file := range st.Compose {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if !containsAny(lower, riskTerms) {
				continue
			}
			serviceRelevant := fileContextContains(file, i, []string{"monero", "moneropay", "btcpay", "wallet-rpc", "monerod", "nginx", "caddy", "traefik", "reverse-proxy"})
			if serviceRelevant {
				warnEv = append(warnEv, evidence(file, i, line))
			} else {
				reviewEv = append(reviewEv, evidence(file, i, line))
			}
		}
	}
	if len(warnEv) > 0 {
		return finding("container_privilege_risk", SeverityWarn, "container privilege risk detected", uniqueEvidence(warnEv), "Review whether host networking or elevated privileges are necessary.")
	}
	if len(reviewEv) > 0 {
		return finding("container_privilege_risk", SeverityReview, "container privilege setting detected on unknown service", uniqueEvidence(reviewEv), "Manual review of compose privileges is needed.")
	}
	return finding("container_privilege_risk", SeverityPass, "container privilege risk not detected", nil, "Keep payment-facing containers least-privileged.")
}

func walletRPCDetected(st state) (bool, []Evidence) {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			if containsAny(strings.ToLower(line), []string{"wallet-rpc", "monero-wallet-rpc", "18082"}) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return len(ev) > 0, uniqueEvidence(ev)
}

func walletPublicExposure(st state) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if publicPortPublish(lower, "18082") ||
				strings.Contains(lower, `"0.0.0.0:18082"`) ||
				strings.Contains(lower, "'0.0.0.0:18082'") ||
				(strings.Contains(lower, "--rpc-bind-ip=0.0.0.0") && fileContextContains(file, i, []string{"wallet-rpc", "monero-wallet-rpc", "18082"})) ||
				(strings.Contains(lower, "--rpc-bind-ip 0.0.0.0") && fileContextContains(file, i, []string{"wallet-rpc", "monero-wallet-rpc", "18082"})) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func monerodPublicExposure(st state) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if publicPortPublish(lower, "18081") ||
				publicPortPublish(lower, "18083") ||
				publicPortPublish(lower, "18089") ||
				(strings.Contains(lower, "--rpc-bind-ip=0.0.0.0") && !fileContextContains(file, i, []string{"wallet-rpc", "monero-wallet-rpc", "18082"})) ||
				(strings.Contains(lower, "--rpc-bind-ip 0.0.0.0") && !fileContextContains(file, i, []string{"wallet-rpc", "monero-wallet-rpc", "18082"})) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func findPublicBindEvidence(st state, ports []string) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			for _, port := range ports {
				if publicPortPublish(lower, port) {
					ev = append(ev, evidence(file, i, line))
				}
			}
		}
	}
	return uniqueEvidence(ev)
}

func rpcLoginDisabled(st state) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "--disable-rpc-login") ||
				strings.Contains(lower, "disable-rpc-login") ||
				strings.Contains(lower, "disable_rpc_login=true") ||
				strings.Contains(lower, "disable-rpc-login=true") {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func walletLocalhostBind(st state) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if containsAny(lower, []string{"127.0.0.1:18082", "localhost:18082"}) ||
				(containsAny(lower, []string{"--rpc-bind-ip=127.0.0.1", "--rpc-bind-ip 127.0.0.1", "--rpc-bind-ip=localhost", "--rpc-bind-ip localhost"}) &&
					fileContextContains(file, i, []string{"wallet-rpc", "monero-wallet-rpc", "18082"})) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func localhostBindEvidence(st state) []Evidence {
	var ev []Evidence
	for _, file := range st.ConfigFiles {
		for i, line := range file.Lines {
			lower := strings.ToLower(line)
			if containsAny(lower, []string{"127.0.0.1:18081", "127.0.0.1:18082", "127.0.0.1:18083", "127.0.0.1:18089", "localhost:18081", "localhost:18082", "--rpc-bind-ip=127.0.0.1", "--rpc-bind-ip 127.0.0.1", "--rpc-bind-ip=localhost", "--rpc-bind-ip localhost"}) {
				ev = append(ev, evidence(file, i, line))
			}
		}
	}
	return uniqueEvidence(ev)
}

func publicPortPublish(line, port string) bool {
	if strings.Contains(line, "127.0.0.1:"+port) || strings.Contains(line, "localhost:"+port) {
		return false
	}
	return strings.Contains(line, "0.0.0.0:"+port) || strings.Contains(line, port+":"+port)
}

func privacyProxySignal(line string) bool {
	if !strings.Contains(line, "proxy") {
		return false
	}
	if strings.Contains(line, "reverse_proxy") || strings.Contains(line, "proxy_pass") {
		return false
	}
	return true
}

func walletLookingPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".keys") || strings.Contains(name, "wallet") || name == "wallet" || name == "wallet.keys"
}

func fileContainsAny(file textFile, terms []string) bool {
	for _, line := range file.Lines {
		if containsAny(strings.ToLower(line), terms) {
			return true
		}
	}
	return false
}

func fileContextContains(file textFile, line int, terms []string) bool {
	start := line - 5
	if start < 0 {
		start = 0
	}
	end := line + 5
	if end >= len(file.Lines) {
		end = len(file.Lines) - 1
	}
	for i := start; i <= end; i++ {
		if containsAny(strings.ToLower(file.Lines[i]), terms) {
			return true
		}
	}
	return false
}

func containsAny(text string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(text, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

func evidence(file textFile, line int, text string) Evidence {
	return Evidence{
		File: file.Display,
		Line: line + 1,
		Text: RedactText(text),
	}
}

func finding(checkID string, severity Severity, title string, ev []Evidence, recommendation string) Finding {
	ev = uniqueEvidence(ev)
	if ev == nil {
		ev = []Evidence{}
	}
	f := Finding{
		CheckID:        checkID,
		Severity:       severity,
		Title:          title,
		Evidence:       ev,
		Recommendation: recommendation,
	}
	if len(f.Evidence) > 0 {
		f.File = f.Evidence[0].File
		f.Line = f.Evidence[0].Line
	}
	return f
}

func copyEvidence(ev []Evidence) []Evidence {
	out := make([]Evidence, len(ev))
	copy(out, ev)
	return out
}

func uniqueEvidence(ev []Evidence) []Evidence {
	if len(ev) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]Evidence, 0, len(ev))
	for _, item := range ev {
		key := item.File + "\x00" + strconv.Itoa(item.Line) + "\x00" + item.Text
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func severityRank(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityWarn:
		return 1
	case SeverityReview:
		return 2
	default:
		return 3
	}
}

func reportStatus(findings []Finding) string {
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			return "critical"
		}
	}
	for _, f := range findings {
		if f.Severity == SeverityWarn {
			return "warn"
		}
	}
	return "ok"
}

func PublicBindAddr(addr string) bool {
	if strings.HasPrefix(addr, "0.0.0.0") || strings.HasPrefix(addr, "[::]") {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr == "" || addr[0] == ':'
	}
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}

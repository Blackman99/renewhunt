// Package scan hunts hardcoded ACME / Let's Encrypt renewal day windows.
package scan

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Severity of a finding.
type Severity string

const (
	Blocked Severity = "BLOCKED"
	Risky   Severity = "RISKY"
	OK      Severity = "OK"
	Info    Severity = "INFO"
)

// Finding is one hit in a file.
type Finding struct {
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Column   int      `json:"column,omitempty"`
	Match    string   `json:"match"`
	Context  string   `json:"context"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
	Hint     string   `json:"hint,omitempty"`
}

// Result is the aggregate of a scan.
type Result struct {
	Findings []Finding `json:"findings"`
	Scanned  int       `json:"files_scanned"`
	Skipped  int       `json:"files_skipped"`
}

// Options controls the scan.
type Options struct {
	System bool // also scan common system paths
}

var skipDirNames = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".svn": true,
	".hg": true, "dist": true, "build": true, "__pycache__": true,
	".terraform": true, "testdata": false, // allow testdata when scanning elsewhere; we still scan it if asked
}

var textExt = map[string]bool{
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	".yml": true, ".yaml": true, ".toml": true, ".json": true,
	".tf": true, ".hcl": true, ".conf": true, ".cfg": true, ".ini": true,
	".service": true, ".timer": true, ".path": true,
	".md": true, ".txt": true, ".env": true,
	".py": true, ".rb": true, ".pl": true, ".go": true,
	".Dockerfile": true, ".makefile": true, ".mk": true,
	".cron": true, ".crontab": true,
}

var textBasenames = map[string]bool{
	"dockerfile": true, "makefile": true, "crontab": true,
	"cron": true, "vagrantfile": true, "procfile": true,
	"certbot": true, "acme.sh": true,
}

// Patterns that capture a renewal-related number with context.
type pattern struct {
	re       *regexp.Regexp
	kind     string // days_since_issue | renew_before_days | renew_before_hours | renew_days_env | days_flag
	groupIdx int    // which submatch is the number
}

var patterns = []pattern{
	{regexp.MustCompile(`(?i)renew.?before.?expiry\s*[=:]\s*(\d+)\s*(d|day|days)?\b`), "renew_before_days", 1},
	{regexp.MustCompile(`(?i)renew_before_expiry\s*[=:]\s*(\d+)`), "renew_before_days", 1},
	{regexp.MustCompile(`(?i)RENEW_DAYS\s*[=:]\s*(\d+)`), "renew_days_env", 1},
	{regexp.MustCompile(`(?i)renewBefore:\s*(\d+)\s*h\b`), "renew_before_hours", 1},
	{regexp.MustCompile(`(?i)renewBefore:\s*(\d+)\s*d\b`), "renew_before_days", 1},
	{regexp.MustCompile(`(?i)--days(?:-until-expiry|-before)?\s+(\d+)`), "days_flag", 1},
	{regexp.MustCompile(`(?i)--renew-before-expiry(?:-days)?\s+(\d+)`), "days_flag", 1},
	{regexp.MustCompile(`(?i)certbot\s+renew[^\n]*--days\s+(\d+)`), "days_flag", 1},
	{regexp.MustCompile(`(?i)renewal[_-]?window\s*[=:]\s*(\d+)`), "days_flag", 1},
}

// Standalone day numbers LE told people to grep for, only when the line
// looks like a renew/cert/acme/letsencrypt/cron context.
var standaloneDays = regexp.MustCompile(`(?i)(?:^|[^\d])(83|80|60|30)(?:[^\d]|$)`)
var renewContext = regexp.MustCompile(`(?i)(renew|certbot|acme|letsencrypt|lets-encrypt|ssl|tls|certificate|cert-manager|lego|caddy|traefik|cert\.pem|fullchain)`)

// SystemPaths are common locations for renewal automation.
var SystemPaths = []string{
	"/etc/letsencrypt",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.hourly",
	"/var/spool/cron",
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/etc/certbot",
	"/root/.acme.sh",
	"/home",
}

// Scan walks paths and returns findings.
func Scan(paths []string, opts Options) (Result, error) {
	var res Result
	seen := map[string]bool{}
	targets := append([]string{}, paths...)
	if opts.System {
		for _, p := range SystemPaths {
			if _, err := os.Stat(p); err == nil {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	for _, root := range targets {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		info, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if f, sk := scanFile(abs); sk {
				res.Skipped++
			} else {
				res.Scanned++
				res.Findings = append(res.Findings, f...)
			}
			continue
		}
		_ = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if skipDirNames[name] {
					return filepath.SkipDir
				}
				return nil
			}
			if f, sk := scanFile(path); sk {
				res.Skipped++
			} else {
				res.Scanned++
				res.Findings = append(res.Findings, f...)
			}
			return nil
		})
	}
	return res, nil
}

func scanFile(path string) ([]Finding, bool /*skipped*/) {
	if !looksTexty(path) {
		return nil, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, true
	}
	if !utf8.Valid(data) || looksBinary(data) {
		return nil, true
	}
	// Cap huge files
	if len(data) > 2<<20 {
		data = data[:2<<20]
	}
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		findings = append(findings, matchLine(path, lineNo, line)...)
	}
	return findings, false
}

func looksTexty(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if textBasenames[base] {
		return true
	}
	if strings.HasPrefix(base, "cron") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	if textExt[ext] {
		return true
	}
	// no extension: allow if name suggests config
	if ext == "" && (strings.Contains(base, "renew") || strings.Contains(base, "acme") || strings.Contains(base, "cert")) {
		return true
	}
	return false
}

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

func matchLine(path string, lineNo int, line string) []Finding {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return nil
	}
	var out []Finding
	seen := map[string]bool{} // dedupe same span
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(line, -1) {
			numStr := line[m[2*p.groupIdx]:m[2*p.groupIdx+1]]
			key := fmt.Sprintf("%d:%s:%s", m[0], p.kind, numStr)
			if seen[key] {
				continue
			}
			seen[key] = true
			var n int
			fmt.Sscanf(numStr, "%d", &n)
			sev, reason, hint := classify(p.kind, n, line[m[0]:m[1]])
			out = append(out, Finding{
				Path: path, Line: lineNo, Column: m[0] + 1,
				Match: line[m[0]:m[1]], Context: strings.TrimSpace(line),
				Severity: sev, Reason: reason, Hint: hint,
			})
		}
	}
	// Standalone LE numbers only in renew context, and only if not already matched
	if renewContext.MatchString(line) {
		for _, m := range standaloneDays.FindAllStringSubmatchIndex(line, -1) {
			numStr := line[m[2]:m[3]]
			key := fmt.Sprintf("standalone:%s", numStr)
			// skip if a structured pattern already covered this number nearby
			already := false
			for _, f := range out {
				if strings.Contains(f.Match, numStr) {
					already = true
					break
				}
			}
			if already || seen[key] {
				continue
			}
			seen[key] = true
			var n int
			fmt.Sscanf(numStr, "%d", &n)
			sev, reason, hint := classifyStandalone(n)
			out = append(out, Finding{
				Path: path, Line: lineNo, Column: m[2] + 1,
				Match: numStr, Context: strings.TrimSpace(line),
				Severity: sev, Reason: reason, Hint: hint,
			})
		}
	}
	return dedupeFindings(out)
}

func dedupeFindings(in []Finding) []Finding {
	if len(in) <= 1 {
		return in
	}
	type span struct{ a, b int }
	var keep []Finding
	for _, f := range in {
		fa, fb := f.Column, f.Column+len(f.Match)
		dominated := false
		for i, k := range keep {
			ka, kb := k.Column, k.Column+len(k.Match)
			if f.Line == k.Line && fa < kb && fb > ka {
				// overlap: keep the longer / more severe
				if len(f.Match) > len(k.Match) || (len(f.Match) == len(k.Match) && severityRank(f.Severity) > severityRank(k.Severity)) {
					keep[i] = f
				}
				dominated = true
				break
			}
		}
		if !dominated {
			keep = append(keep, f)
		}
	}
	return keep
}

func severityRank(s Severity) int {
	switch s {
	case Blocked:
		return 3
	case Risky:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// classify maps a numeric window to severity for LE 64-day (then 45-day) certs.
// LE guidance: renew near ⅔ of lifetime ≈ day 43 for 64-day, ≈ day 30 for 45-day.
func classify(kind string, n int, raw string) (Severity, string, string) {
	hint := "Prefer ~⅔ of lifetime (≈ day 43 for 64-day, ≈ day 30 for 45-day), or ARI / percentage-based renewBefore."
	switch kind {
	case "renew_before_hours":
		days := float64(n) / 24.0
		if days >= 60 {
			return Blocked, fmt.Sprintf("renewBefore %dh (≈%.0fd before expiry) is longer than a 64-day cert lifetime margin — absolute windows break on short profiles", n, days), hint
		}
		if days >= 45 {
			return Risky, fmt.Sprintf("renewBefore %dh (≈%.0fd) leaves little or no margin under 64-day certs; fails under 45-day", n, days), hint
		}
		if days > 21 {
			return Risky, fmt.Sprintf("renewBefore %dh (≈%.1fd) is an absolute window; check against 45-day profile", n, days), hint
		}
		return OK, fmt.Sprintf("renewBefore %dh (≈%.1fd) is within short-lifetime margins", n, days), ""
	case "renew_before_days", "days_flag", "renew_days_env":
		return classifyDaysBeforeExpiry(n)
	default:
		return classifyStandalone(n)
	}
}

// classifyDaysBeforeExpiry: n = days before expiry to renew.
func classifyDaysBeforeExpiry(n int) (Severity, string, string) {
	hint := "Prefer ~⅔ of lifetime (≈ day 43 since issuance for 64-day = renew ~21d before expiry), or ARI."
	// For 64-day cert: renew at ⅔ ⇒ ~21 days before expiry.
	// Absolute "renew 30 days before expiry" on a 64-day cert renews at day 34 — OK-ish.
	// Absolute "renew 60 days before expiry" on a 64-day cert renews at day 4 — RISKY/weird.
	// Absolute "renew 80 days before expiry" on a 90-day cert renews at day 10; on 64-day it's impossible (past expiry conceptually for the old model).
	if n >= 64 {
		return Blocked, fmt.Sprintf("renew %d days before expiry cannot work: 64-day (and shorter) certificates never reach that age-remaining", n), hint
	}
	if n >= 45 {
		return Risky, fmt.Sprintf("renew %d days before expiry leaves ≤%d days of life used on a 64-day cert; breaks under 45-day profile", n, 64-n), hint
	}
	if n > 30 {
		return Risky, fmt.Sprintf("renew %d days before expiry is a large absolute window; under 45-day certs margin is tight", n), hint
	}
	if n >= 14 && n <= 30 {
		return OK, fmt.Sprintf("renew %d days before expiry fits 64-day (~⅔ guidance ≈21d) and often 45-day profiles", n), ""
	}
	if n < 7 {
		return Risky, fmt.Sprintf("renew only %d days before expiry leaves a thin safety margin", n), hint
	}
	return Info, fmt.Sprintf("renew %d days before expiry — verify against your CA's lifetime", n), hint
}

// classifyStandalone: n is a day-since-issuance style number LE asked people to grep (83, 80, 60, 30).
func classifyStandalone(n int) (Severity, string, string) {
	hint := "Let's Encrypt: renew near ⅔ of lifetime (≈ day 43 for 64-day). Grep targets 83/80/60 were common for 90-day certs."
	switch n {
	case 83, 80:
		return Blocked, fmt.Sprintf("hardcoded day %d since issuance is past 64-day certificate expiry — renewal never fires in time", n), hint
	case 60:
		return Risky, "hardcoded day 60 since issuance leaves only ~4 days of margin on a 64-day cert; fails under 45-day", hint
	case 30:
		return Info, "day 30 since issuance may be OK for 64-day (before ⅔) but is late for 45-day (⅔ ≈ day 30) — prefer percentage or ARI", hint
	default:
		if n > 64 {
			return Blocked, fmt.Sprintf("day %d since issuance exceeds 64-day lifetime", n), hint
		}
		if n > 43 {
			return Risky, fmt.Sprintf("day %d since issuance is after the ⅔ mark for 64-day certs", n), hint
		}
		return Info, fmt.Sprintf("day %d in renew/cert context — review against 64-day / 45-day profiles", n), hint
	}
}

// HasBlocked reports whether any finding is BLOCKED.
func (r Result) HasBlocked() bool {
	for _, f := range r.Findings {
		if f.Severity == Blocked {
			return true
		}
	}
	return false
}

// Worst returns the highest severity present.
func (r Result) Worst() Severity {
	order := map[Severity]int{Blocked: 3, Risky: 2, Info: 1, OK: 0}
	worst := OK
	for _, f := range r.Findings {
		if order[f.Severity] > order[worst] {
			worst = f.Severity
		}
	}
	return worst
}

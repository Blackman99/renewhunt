// renewhunt tells you whether your ACME renewal setup will survive
// Let's Encrypt's move to 64-day (then 45-day) certificates.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Blackman99/renewhunt/clients"
	"github.com/Blackman99/renewhunt/live"
	"github.com/Blackman99/renewhunt/scan"
	"github.com/Blackman99/renewhunt/timers"
)

var version = "dev"

const usage = `renewhunt - will your ACME renewal survive 64-day Let's Encrypt certs?

Usage:
  renewhunt [flags] [paths...]       run scan + clients + timers (default)
  renewhunt scan [flags] [paths...]  hunt hardcoded renewal day windows
  renewhunt live [flags] host...     probe served certs: lifetime, age, renewal timing
  renewhunt clients                  probe ACME clients on PATH
  renewhunt timers                   list systemd / cron renew schedulers

Flags:
  -json                print JSON
  -system              also scan common system paths (/etc/letsencrypt, cron, systemd, ...)
  -check-live hosts    default command: also probe these hosts (comma-separated, repeatable)
  -timeout 10s         live probe timeout per host
  -version             print version

Exit codes: 0 ok, 1 any BLOCKED finding, 2 usage or I/O error.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return cmdScan(args[1:], out, errw)
		case "live":
			return cmdLive(args[1:], out, errw)
		case "clients":
			return cmdClients(args[1:], out, errw)
		case "timers":
			return cmdTimers(args[1:], out, errw)
		case "help", "-h", "--help":
			fmt.Fprint(errw, usage)
			return 0
		case "-version", "--version", "version":
			fmt.Fprintln(out, "renewhunt", version)
			return 0
		}
	}
	return cmdAll(args, out, errw)
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

type common struct {
	paths   []string
	json    bool
	system  bool
	version bool
	live    []string
	timeout time.Duration
}

func parseCommon(args []string, errw io.Writer) (common, error) {
	var c common
	var hosts listFlag
	fs := flag.NewFlagSet("renewhunt", flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.Usage = func() { fmt.Fprint(errw, usage) }
	fs.BoolVar(&c.json, "json", false, "print JSON")
	fs.BoolVar(&c.system, "system", false, "also scan common system paths")
	fs.BoolVar(&c.version, "version", false, "print version")
	fs.Var(&hosts, "check-live", "probe these hosts (comma-separated, repeatable)")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Second, "live probe timeout per host")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.paths = fs.Args()
	c.live = live.ParseTargets(hosts)
	return c, nil
}

func encode(out io.Writer, v any) {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func cmdAll(args []string, out, errw io.Writer) int {
	c, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if c.version {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	if len(c.paths) == 0 {
		c.paths = []string{"."}
	}
	sres, err := scan.Scan(c.paths, scan.Options{System: c.system})
	if err != nil {
		fmt.Fprintln(errw, "renewhunt:", err)
		return 2
	}
	cinfo := clients.Probe()
	tres := timers.Probe()
	var lres []live.Result
	if len(c.live) > 0 {
		lres = live.Probe(context.Background(), c.live, live.Options{Timeout: c.timeout})
	}
	if c.json {
		doc := map[string]any{"scan": sres, "clients": cinfo, "timers": tres}
		if lres != nil {
			doc["live"] = lres
		}
		encode(out, doc)
	} else {
		printScan(out, sres)
		fmt.Fprintln(out)
		if lres != nil {
			printLive(out, lres)
			fmt.Fprintln(out)
		}
		printClients(out, cinfo)
		fmt.Fprintln(out)
		printTimers(out, tres)
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Guidance: Let's Encrypt moves staging to 64-day on 2026-10-14, production 2027-02-10; renew near ⅔ lifetime (≈ day 43).\n")
		fmt.Fprintf(out, "See https://letsencrypt.org/2026/10/07/64-day-certs\n")
	}
	if sres.HasBlocked() || live.HasBlocked(lres) {
		return 1
	}
	return 0
}

func cmdScan(args []string, out, errw io.Writer) int {
	c, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if c.version {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	if len(c.paths) == 0 {
		c.paths = []string{"."}
	}
	sres, err := scan.Scan(c.paths, scan.Options{System: c.system})
	if err != nil {
		fmt.Fprintln(errw, "renewhunt:", err)
		return 2
	}
	if c.json {
		encode(out, sres)
	} else {
		printScan(out, sres)
	}
	if sres.HasBlocked() {
		return 1
	}
	return 0
}

func cmdLive(args []string, out, errw io.Writer) int {
	c, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if c.version {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	targets := live.ParseTargets(append(c.live, c.paths...))
	if len(targets) == 0 {
		fmt.Fprintln(errw, "renewhunt live: name at least one host, e.g. renewhunt live example.com api.example.com:8443")
		return 2
	}
	lres := live.Probe(context.Background(), targets, live.Options{Timeout: c.timeout})
	if c.json {
		encode(out, lres)
	} else {
		printLive(out, lres)
	}
	if live.HasBlocked(lres) {
		return 1
	}
	return 0
}

func cmdClients(args []string, out, errw io.Writer) int {
	c, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if c.version {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	cinfo := clients.Probe()
	if c.json {
		encode(out, cinfo)
	} else {
		printClients(out, cinfo)
	}
	return 0
}

func cmdTimers(args []string, out, errw io.Writer) int {
	c, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if c.version {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	tres := timers.Probe()
	if c.json {
		encode(out, tres)
	} else {
		printTimers(out, tres)
	}
	return 0
}

// displayPath shortens absolute paths under the working directory.
func displayPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}

func printScan(out io.Writer, r scan.Result) {
	fmt.Fprintf(out, "SCAN  files=%d skipped=%d findings=%d worst=%s\n", r.Scanned, r.Skipped, len(r.Findings), r.Worst())
	if len(r.Findings) == 0 {
		fmt.Fprintln(out, "  (no hardcoded renewal windows found)")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEV\tFILE:LINE\tMATCH\tREASON")
	for _, f := range r.Findings {
		loc := fmt.Sprintf("%s:%d", displayPath(f.Path), f.Line)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, loc, truncate(f.Match, 40), truncate(f.Reason, 100))
		if f.Suggestion != "" {
			fmt.Fprintf(tw, "\t\tfix: %s\t%s\n", f.Suggestion, "(cert-manager ≥ v1.16; or delete renewBefore to use the ⅓-lifetime default)")
		}
	}
	tw.Flush()
}

func printLive(out io.Writer, rs []live.Result) {
	worst := "OK"
	rank := map[live.Severity]int{live.Blocked: 3, live.Risky: 2, live.Info: 1, live.OK: 0}
	for _, r := range rs {
		if rank[r.Severity] > rank[live.Severity(worst)] {
			worst = string(r.Severity)
		}
	}
	fmt.Fprintf(out, "LIVE  hosts=%d worst=%s\n", len(rs), worst)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEV\tHOST\tLIFETIME\tUSED\tLEFT\tISSUER\tREASON")
	for _, r := range rs {
		if r.Error != "" {
			fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t%s\n", r.Severity, r.Target, truncate(r.Reason, 100))
			continue
		}
		used, left := fmt.Sprintf("%.0f%%", r.ElapsedPct), fmt.Sprintf("%.1fd", r.RemainDays)
		if r.RemainDays <= 0 {
			used, left = "100%", "expired"
		} else if r.ElapsedPct < 0 {
			used = "0%"
		}
		fmt.Fprintf(tw, "%s\t%s\t%.0fd\t%s\t%s\t%s\t%s\n", r.Severity, r.Target, r.LifetimeDays, used, left, truncate(r.IssuerOrg, 24), truncate(r.Reason, 100))
	}
	tw.Flush()
}

func printClients(out io.Writer, list []clients.Info) {
	fmt.Fprintln(out, "CLIENTS")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFOUND\tVERSION\tNOTE")
	for _, c := range list {
		found := "no"
		if c.Found {
			found = "yes"
		}
		note := c.Note
		if c.ARI != "" {
			if note != "" {
				note += " | "
			}
			note += c.ARI
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.Name, found, truncate(c.Version, 40), truncate(note, 120))
	}
	tw.Flush()
}

func printTimers(out io.Writer, r timers.Report) {
	fmt.Fprintln(out, "TIMERS / CRON")
	if len(r.Entries) == 0 {
		fmt.Fprintln(out, "  (none found)")
	} else {
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SOURCE\tNAME\tDETAIL")
		for _, e := range r.Entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Source, e.Name, truncate(e.Detail, 100))
		}
		tw.Flush()
	}
	if r.SchedulerNote != "" {
		fmt.Fprintln(out, " ", r.SchedulerNote)
	}
}

// truncate shortens s to n runes (not bytes, so "⅔" and "≈" never split).
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

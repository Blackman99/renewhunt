// renewhunt tells you whether your ACME renewal setup will survive
// Let's Encrypt's move to 64-day (then 45-day) certificates.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/Blackman99/renewhunt/clients"
	"github.com/Blackman99/renewhunt/scan"
	"github.com/Blackman99/renewhunt/timers"
)

var version = "dev"

const usage = `renewhunt - will your ACME renewal survive 64-day Let's Encrypt certs?

Usage:
  renewhunt [flags]                  run scan + clients + timers (default)
  renewhunt scan [flags] [paths...]  hunt hardcoded renewal day windows
  renewhunt clients                  probe ACME clients on PATH
  renewhunt timers                   list systemd / cron renew schedulers

Flags:
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return cmdScan(args[1:], out, errw)
		case "clients":
			return cmdClients(args[1:], out, errw)
		case "timers":
			return cmdTimers(args[1:], out, errw)
		case "help", "-h", "--help":
			fmt.Fprint(errw, usage)
			fmt.Fprintln(errw, "  -json          print JSON")
			fmt.Fprintln(errw, "  -system        also scan common system paths")
			fmt.Fprintln(errw, "  -version       print version")
			return 0
		case "-version", "--version", "version":
			fmt.Fprintln(out, "renewhunt", version)
			return 0
		}
	}
	return cmdAll(args, out, errw)
}

func parseCommon(args []string, errw io.Writer) (paths []string, asJSON, system, showVer bool, err error) {
	fs := flag.NewFlagSet("renewhunt", flag.ContinueOnError)
	fs.SetOutput(errw)
	j := fs.Bool("json", false, "print JSON")
	sys := fs.Bool("system", false, "also scan common system paths (/etc/letsencrypt, cron, systemd, …)")
	ver := fs.Bool("version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return nil, false, false, false, err
	}
	return fs.Args(), *j, *sys, *ver, nil
}

func cmdAll(args []string, out, errw io.Writer) int {
	paths, asJSON, system, showVer, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if showVer {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	sres, err := scan.Scan(paths, scan.Options{System: system})
	if err != nil {
		fmt.Fprintln(errw, "renewhunt:", err)
		return 2
	}
	cinfo := clients.Probe()
	tres := timers.Probe()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"scan":    sres,
			"clients": cinfo,
			"timers":  tres,
		})
	} else {
		printScan(out, sres)
		fmt.Fprintln(out)
		printClients(out, cinfo)
		fmt.Fprintln(out)
		printTimers(out, tres)
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Guidance: Let's Encrypt moves staging to 64-day on 2026-10-14, production 2027-02-10; renew near ⅔ lifetime (≈ day 43).\n")
		fmt.Fprintf(out, "See https://letsencrypt.org/2026/10/07/64-day-certs\n")
	}
	if sres.HasBlocked() {
		return 1
	}
	return 0
}

func cmdScan(args []string, out, errw io.Writer) int {
	paths, asJSON, system, showVer, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if showVer {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	sres, err := scan.Scan(paths, scan.Options{System: system})
	if err != nil {
		fmt.Fprintln(errw, "renewhunt:", err)
		return 2
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sres)
	} else {
		printScan(out, sres)
	}
	if sres.HasBlocked() {
		return 1
	}
	return 0
}

func cmdClients(args []string, out, errw io.Writer) int {
	_, asJSON, _, showVer, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if showVer {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	cinfo := clients.Probe()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cinfo)
	} else {
		printClients(out, cinfo)
	}
	return 0
}

func cmdTimers(args []string, out, errw io.Writer) int {
	_, asJSON, _, showVer, err := parseCommon(args, errw)
	if err != nil {
		return 2
	}
	if showVer {
		fmt.Fprintln(out, "renewhunt", version)
		return 0
	}
	tres := timers.Probe()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(tres)
	} else {
		printTimers(out, tres)
	}
	return 0
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
		loc := fmt.Sprintf("%s:%d", f.Path, f.Line)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, loc, truncate(f.Match, 40), truncate(f.Reason, 100))
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

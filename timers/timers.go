// Package timers lists systemd timers and crontab lines related to ACME renewal.
package timers

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Entry is one scheduled renew-related job.
type Entry struct {
	Source  string `json:"source"` // systemd | crontab | cron.d
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Warning string `json:"warning,omitempty"`
}

// Report aggregates scheduler discovery.
type Report struct {
	Entries       []Entry `json:"entries"`
	CertsExist    bool    `json:"letsencrypt_certs_present"`
	NoScheduler   bool    `json:"no_scheduler_warning"`
	SchedulerNote string  `json:"scheduler_note,omitempty"`
}

// Probe lists renew-related timers/cron and warns if certs exist with no scheduler.
func Probe() Report {
	r := Report{}
	r.CertsExist = dirHasCerts("/etc/letsencrypt/live")
	r.Entries = append(r.Entries, systemdTimers()...)
	r.Entries = append(r.Entries, crontabLines()...)
	r.Entries = append(r.Entries, cronDLines()...)
	if r.CertsExist && len(r.Entries) == 0 {
		r.NoScheduler = true
		r.SchedulerNote = "WARN: /etc/letsencrypt/live has certificates but no certbot/acme/letsencrypt systemd timer or crontab renew line was found"
	}
	if !r.CertsExist && len(r.Entries) == 0 {
		r.SchedulerNote = "no renew schedulers found (and no /etc/letsencrypt/live certs on this host)"
	}
	return r
}

func dirHasCerts(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.IsDir() && e.Name() != "README" {
			return true
		}
	}
	return false
}

func systemdTimers() []Entry {
	out, err := exec.Command("systemctl", "list-timers", "--all", "--no-pager").CombinedOutput()
	if err != nil {
		return nil
	}
	var entries []Entry
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		low := strings.ToLower(line)
		if strings.Contains(low, "certbot") || strings.Contains(low, "acme") || strings.Contains(low, "letsencrypt") || strings.Contains(low, "renew") {
			fields := strings.Fields(line)
			name := line
			if len(fields) > 0 {
				name = fields[len(fields)-1]
			}
			entries = append(entries, Entry{Source: "systemd", Name: name, Detail: strings.TrimSpace(line)})
		}
	}
	// also peek unit files
	for _, dir := range []string{"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			n := strings.ToLower(d.Name())
			if strings.HasSuffix(n, ".timer") && (strings.Contains(n, "certbot") || strings.Contains(n, "acme") || strings.Contains(n, "letsencrypt")) {
				entries = append(entries, Entry{Source: "systemd", Name: d.Name(), Detail: path})
			}
			return nil
		})
	}
	return entries
}

func crontabLines() []Entry {
	var entries []Entry
	for _, args := range [][]string{{"crontab", "-l"}, {"crontab", "-u", "root", "-l"}} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			continue
		}
		entries = append(entries, filterCron("crontab", string(out))...)
	}
	return entries
}

func cronDLines() []Entry {
	var entries []Entry
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, e := range filterCron("cron.d:"+path, string(data)) {
				entries = append(entries, e)
			}
			return nil
		})
	}
	return entries
}

func filterCron(source, body string) []Entry {
	var entries []Entry
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "certbot") || strings.Contains(low, "acme") || strings.Contains(low, "letsencrypt") ||
			(strings.Contains(low, "renew") && (strings.Contains(low, "ssl") || strings.Contains(low, "cert"))) {
			entries = append(entries, Entry{Source: source, Name: "renew-line", Detail: line})
		}
	}
	return entries
}

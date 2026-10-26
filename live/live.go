// Package live probes certificates served by hosts you name and judges
// whether their renewal timing still holds up as lifetimes shrink to
// 64 and then 45 days.
//
// It opens a TLS connection to the hosts given on the command line. Only
// with Options.ARI does it also ask the issuing CA for its suggested renewal
// window (two read-only GETs, see package ari).
package live

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Blackman99/renewhunt/ari"
)

// Severity mirrors scan.Severity values so output stays uniform.
type Severity string

const (
	Blocked Severity = "BLOCKED"
	Risky   Severity = "RISKY"
	OK      Severity = "OK"
	Info    Severity = "INFO"
)

// Result is one probed host.
type Result struct {
	Target       string    `json:"target"`
	Address      string    `json:"address,omitempty"`
	Severity     Severity  `json:"severity"`
	Reason       string    `json:"reason"`
	Hint         string    `json:"hint,omitempty"`
	Error        string    `json:"error,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	IssuerOrg    string    `json:"issuer_org,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	LifetimeDays float64   `json:"lifetime_days,omitempty"`
	AgeDays      float64   `json:"age_days,omitempty"`
	RemainDays   float64   `json:"remaining_days,omitempty"`
	ElapsedPct   float64   `json:"elapsed_pct,omitempty"`
	ChainValid   bool      `json:"chain_valid"`
	ChainError   string    `json:"chain_error,omitempty"`
	ARI          *ari.Info `json:"ari,omitempty"`
}

// Options controls probing.
type Options struct {
	Timeout time.Duration
	// Roots overrides the system root pool (tests).
	Roots *x509.CertPool
	// Now overrides the clock (tests).
	Now func() time.Time
	// ARI asks the issuing CA for its suggested renewal window (RFC 9773).
	ARI bool
	// ARIDirectory overrides issuer-based ACME directory detection.
	ARIDirectory string
	// ARIClient overrides the HTTP client used for ARI (tests).
	ARIClient *http.Client
}

// ParseTargets splits comma-separated and repeated host arguments.
func ParseTargets(args []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range args {
		for _, t := range strings.Split(a, ",") {
			t = strings.TrimSpace(t)
			t = strings.TrimPrefix(t, "https://")
			t = strings.TrimSuffix(t, "/")
			if i := strings.Index(t, "/"); i >= 0 {
				t = t[:i]
			}
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// splitTarget returns dial address and SNI server name.
func splitTarget(t string) (addr, sni string) {
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		host, port = t, "443"
	}
	host = strings.Trim(host, "[]")
	return net.JoinHostPort(host, port), host
}

// Probe connects to each target and classifies its leaf certificate.
func Probe(ctx context.Context, targets []string, opts Options) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		out = append(out, probeOne(ctx, t, opts))
	}
	return out
}

func probeOne(ctx context.Context, target string, opts Options) Result {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	addr, sni := splitTarget(target)
	r := Result{Target: target, Address: addr}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// Verification is done below so an untrusted chain is still reported
		// with its dates instead of failing the whole probe.
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}, //nolint:gosec
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		r.Severity = Blocked
		r.Error = err.Error()
		r.Reason = "could not complete a TLS handshake: " + shortErr(err)
		r.Hint = "Check the host name and port, or that the service is up; renewhunt cannot judge renewal timing without a certificate."
		return r
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		r.Severity = Blocked
		r.Reason = "server sent no certificate"
		return r
	}
	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       sni,
		Intermediates: inter,
		Roots:         opts.Roots,
		CurrentTime:   now(),
	})
	r.ChainValid = verr == nil
	if verr != nil {
		r.ChainError = verr.Error()
	}
	r.Subject = leaf.Subject.CommonName
	if r.Subject == "" && len(leaf.DNSNames) > 0 {
		r.Subject = leaf.DNSNames[0]
	}
	r.Issuer = issuerName(leaf)
	r.IssuerOrg = strings.Join(leaf.Issuer.Organization, ", ")
	if r.IssuerOrg == "" {
		r.IssuerOrg = leaf.Issuer.CommonName
	}
	fill(&r, leaf.NotBefore, leaf.NotAfter, now())
	if opts.ARI {
		info := ari.Lookup(ctx, leaf, ari.Options{Directory: opts.ARIDirectory, Client: opts.ARIClient, Timeout: timeout})
		r.ARI = &info
		ApplyARI(&r, now())
	}
	return r
}

var rank = map[Severity]int{OK: 0, Info: 1, Risky: 2, Blocked: 3}

// ApplyARI folds the CA's suggested renewal window into r.
//
// The CA knows things the dates alone don't: a mass revocation moves the
// window forward, and a client that ignores ARI keeps serving a certificate
// the CA has asked it to replace.
func ApplyARI(r *Result, now time.Time) {
	a := r.ARI
	if a == nil || a.Status != "window" || r.RemainDays <= 0 {
		return
	}
	life := r.NotAfter.Sub(r.NotBefore)
	early := life > 0 && a.WindowStart.Before(r.NotBefore.Add(life/2))
	var sev Severity
	var why string
	switch {
	case now.After(a.WindowEnd):
		sev = Risky
		why = fmt.Sprintf("past the CA's ARI renewal window (ended %s) and still served — the client ignores ARI or renewal is failing", a.WindowEnd.Format("2006-01-02"))
		if early {
			sev = Blocked
			why = "the CA asked for early replacement (window ended " + a.WindowEnd.Format("2006-01-02") + ") — likely a revocation; replace this certificate now"
		}
	case !now.Before(a.WindowStart):
		sev = Info
		why = "inside the CA's ARI renewal window — an ARI-aware client renews now"
		if early {
			sev = Risky
			why = "the CA asked for early replacement (window opened " + a.WindowStart.Format("2006-01-02") + ") — likely a revocation; renew now"
		}
	default:
		sev = OK
		why = fmt.Sprintf("CA suggests renewing %s – %s", a.WindowStart.Format("2006-01-02"), a.WindowEnd.Format("2006-01-02"))
		if early {
			sev = Risky
			why = "the CA moved this certificate's renewal window early (" + a.WindowStart.Format("2006-01-02") + ") — likely a revocation"
		}
	}
	if a.ExplanationURL != "" && (sev == Risky || sev == Blocked) {
		why += " (" + a.ExplanationURL + ")"
	}
	if rank[sev] > rank[r.Severity] {
		r.Severity = sev
		r.Reason = why + "; " + r.Reason
		r.Hint = "Use an ARI-aware client (Certbot 4.1+, recent lego, cert-manager with ARI) so the CA's window drives renewal, then reload the server."
	} else if sev != OK {
		r.Reason += "; " + why
	}
}

func issuerName(c *x509.Certificate) string {
	org := strings.Join(c.Issuer.Organization, ", ")
	cn := c.Issuer.CommonName
	switch {
	case org != "" && cn != "":
		return org + " " + cn
	case cn != "":
		return cn
	default:
		return org
	}
}

func shortErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

const day = 24 * time.Hour

func fill(r *Result, nb, na, now time.Time) {
	r.NotBefore, r.NotAfter = nb.UTC(), na.UTC()
	life := na.Sub(nb)
	r.LifetimeDays = round1(life.Hours() / 24)
	r.AgeDays = round1(now.Sub(nb).Hours() / 24)
	r.RemainDays = round1(na.Sub(now).Hours() / 24)
	if life > 0 {
		r.ElapsedPct = round1(100 * float64(now.Sub(nb)) / float64(life))
	}
	r.Severity, r.Reason, r.Hint = Classify(nb, na, now)
	if !r.ChainValid && r.ChainError != "" && r.RemainDays > 0 && !now.Before(nb) {
		// Dates are judged above; a chain that does not verify is a separate
		// problem worth surfacing but not a renewal-timing failure by itself.
		if r.Severity == OK || r.Severity == Info {
			r.Severity = Risky
		}
		r.Reason = "chain does not verify (" + firstLine(r.ChainError) + "); " + r.Reason
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func round1(f float64) float64 {
	if f < 0 {
		return -float64(int(-f*10+0.5)) / 10
	}
	return float64(int(f*10+0.5)) / 10
}

// Classify judges renewal timing from a leaf's validity window.
//
// A healthy client renews at about ⅔ of lifetime. If a certificate is well
// past that point and still being served, renewal is late or broken — and a
// fixed "N days before expiry" window that barely works today will not work
// once the same CA issues 64-day or 45-day certificates.
func Classify(nb, na, now time.Time) (Severity, string, string) {
	life := na.Sub(nb)
	remain := na.Sub(now)
	lifeD := life.Hours() / 24
	remainD := remain.Hours() / 24
	hint := "Renew at about ⅔ of lifetime (≈ day 43 of 64, ≈ day 30 of 45): use ARI, certbot's default, or cert-manager renewBeforePercentage: 33."
	if life <= 0 {
		return Blocked, "certificate validity window is empty or inverted", hint
	}
	if now.Before(nb) {
		return Risky, fmt.Sprintf("certificate is not valid yet (starts in %.1fd) — check the host clock or a pre-issued deploy", -now.Sub(nb).Hours()/24), ""
	}
	if remain <= 0 {
		return Blocked, fmt.Sprintf("certificate expired %.1fd ago — renewal did not run or was not deployed", -remainD), hint
	}
	elapsed := float64(now.Sub(nb)) / float64(life)
	if remain < 7*day {
		return Blocked, fmt.Sprintf("under 7 days left — renewal is overdue; a client waiting for a fixed day count may never fire in time"), hint
	}
	if elapsed > 0.80 {
		return Risky, "past the ⅔ renewal point and still served — renewal is late, failing, or not reloaded by the server", hint
	}
	switch {
	case lifeD <= 50:
		return OK, "already on a short-lifetime certificate and renewing on time", ""
	case lifeD <= 70:
		return OK, "already on a 64-day-class certificate; the next renewal proves your window works", ""
	case lifeD <= 100:
		return Info, "90-day era certificate, fine today; Let's Encrypt production moves to 64-day on 2027-02-10", "Make sure scan finds no BLOCKED windows before your issuer shortens lifetimes."
	default:
		return Info, "long-lived certificate (not ACME-style); public TLS is capped at 200 days since 2026-03-15 and keeps shrinking", ""
	}
}

// HasBlocked reports whether any result is BLOCKED.
func HasBlocked(rs []Result) bool {
	for _, r := range rs {
		if r.Severity == Blocked {
			return true
		}
	}
	return false
}

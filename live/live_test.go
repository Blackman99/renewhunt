package live

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Blackman99/renewhunt/ari"
)

var t0 = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		age, life float64 // days
		want      Severity
	}{
		{"fresh 90d", 10, 90, Info},
		{"fresh 64d", 20, 64, OK},
		{"fresh 45d", 10, 45, OK},
		{"90d at 85%", 77, 90, Risky},
		{"64d at day 60", 60, 64, Blocked},
		{"expired", 91, 90, Blocked},
		{"long-lived", 30, 398, Info},
	}
	for _, c := range cases {
		nb := t0.Add(-time.Duration(c.age * float64(day)))
		na := nb.Add(time.Duration(c.life * float64(day)))
		got, reason, _ := Classify(nb, na, t0)
		if got != c.want {
			t.Errorf("%s: got %s want %s (%s)", c.name, got, c.want, reason)
		}
	}
	if got, _, _ := Classify(t0.Add(day), t0.Add(65*day), t0); got != Risky {
		t.Errorf("not-yet-valid: got %s", got)
	}
}

func TestParseTargets(t *testing.T) {
	got := ParseTargets([]string{"a.example, https://b.example/path", "a.example", "c.example:8443"})
	want := []string{"a.example", "b.example", "c.example:8443"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSplitTarget(t *testing.T) {
	addr, sni := splitTarget("example.com")
	if addr != "example.com:443" || sni != "example.com" {
		t.Fatalf("got %s %s", addr, sni)
	}
	addr, sni = splitTarget("[::1]:8443")
	if addr != "[::1]:8443" || sni != "::1" {
		t.Fatalf("got %s %s", addr, sni)
	}
}

// serve starts a TLS server whose leaf has the given validity window and
// returns its address plus a root pool that trusts it.
func serve(t *testing.T, nb, na time.Time) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		Issuer:                pkix.Name{CommonName: "renewhunt test CA"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return strings.TrimPrefix(srv.URL, "https://"), pool
}

func TestProbeLive(t *testing.T) {
	now := time.Now()
	addr, pool := serve(t, now.Add(-20*day), now.Add(44*day)) // 64d cert, 20d old
	_, port, _ := net.SplitHostPort(addr)
	rs := Probe(context.Background(), []string{"localhost:" + port}, Options{Roots: pool, Timeout: 5 * time.Second})
	if len(rs) != 1 {
		t.Fatalf("want 1 result, got %d", len(rs))
	}
	r := rs[0]
	if r.Error != "" || !r.ChainValid {
		t.Fatalf("unexpected error: %+v", r)
	}
	if r.Severity != OK || r.LifetimeDays != 64 {
		t.Fatalf("got %s lifetime=%v reason=%s", r.Severity, r.LifetimeDays, r.Reason)
	}
}

func TestProbeLiveUntrustedOverdue(t *testing.T) {
	now := time.Now()
	addr, _ := serve(t, now.Add(-85*day), now.Add(5*day)) // 90d, 5d left
	rs := Probe(context.Background(), []string{addr}, Options{Roots: x509.NewCertPool(), Timeout: 5 * time.Second})
	r := rs[0]
	if r.ChainValid {
		t.Fatal("expected untrusted chain")
	}
	if r.Severity != Blocked {
		t.Fatalf("got %s: %s", r.Severity, r.Reason)
	}
	if !HasBlocked(rs) {
		t.Fatal("HasBlocked false")
	}
}

func TestProbeUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	r := Probe(context.Background(), []string{addr}, Options{Timeout: 2 * time.Second})[0]
	if r.Severity != Blocked || r.Error == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestApplyARI(t *testing.T) {
	nb := t0.Add(-30 * day)
	na := nb.Add(90 * day)
	mk := func(start, end time.Time) Result {
		r := Result{ChainValid: true}
		fill(&r, nb, na, t0)
		r.ARI = &ari.Info{Status: "window", WindowStart: start, WindowEnd: end, ExplanationURL: "https://example.test/incident"}
		return r
	}
	cases := []struct {
		name       string
		start, end time.Time
		want       Severity
		reasonHas  string
	}{
		{"normal, ahead", nb.Add(60 * day), nb.Add(62 * day), Info, "90-day era"},
		{"early window ahead (revocation)", nb.Add(35 * day), nb.Add(36 * day), Risky, "early"},
		{"early window open", nb.Add(29 * day), nb.Add(31 * day), Risky, "renew now"},
		{"early window missed", nb.Add(25 * day), nb.Add(26 * day), Blocked, "replace this certificate now"},
	}
	for _, c := range cases {
		r := mk(c.start, c.end)
		ApplyARI(&r, t0)
		if r.Severity != c.want || !strings.Contains(r.Reason, c.reasonHas) {
			t.Errorf("%s: got %s %q", c.name, r.Severity, r.Reason)
		}
	}
	// A 64-day cert past its normal (late) ARI window: still served → RISKY.
	nb2 := t0.Add(-46 * day)
	r := Result{ChainValid: true}
	fill(&r, nb2, nb2.Add(64*day), t0)
	r.ARI = &ari.Info{Status: "window", WindowStart: nb2.Add(42 * day), WindowEnd: nb2.Add(44 * day)}
	ApplyARI(&r, t0)
	if r.Severity != Risky || !strings.Contains(r.Reason, "past the CA's ARI renewal window") {
		t.Errorf("missed normal window: got %s %q", r.Severity, r.Reason)
	}
	// Non-window statuses never change severity.
	r = Result{ChainValid: true}
	fill(&r, nb, na, t0)
	before := r.Severity
	r.ARI = &ari.Info{Status: "unsupported"}
	ApplyARI(&r, t0)
	if r.Severity != before {
		t.Errorf("unsupported changed severity to %s", r.Severity)
	}
}

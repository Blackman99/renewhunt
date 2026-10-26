package ari

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func cert(org string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		AuthorityKeyId: []byte{0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3, 0x7B, 0x84, 0x7B, 0xA0, 0xAE, 0x2C, 0xDE, 0x01, 0xC8, 0xD4},
		Issuer:         pkix.Name{Organization: []string{org}},
	}
}

// RFC 9773 §4.1 example: AKI 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4
// and serial 00:87:65:43:21 give "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".
func TestCertIDRFCExample(t *testing.T) {
	c := cert("x", 0x87654321)
	got, err := CertID(c)
	if err != nil {
		t.Fatal(err)
	}
	if want := "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCertIDNoAKI(t *testing.T) {
	c := cert("x", 1)
	c.AuthorityKeyId = nil
	if _, err := CertID(c); err == nil {
		t.Fatal("expected error without AKI")
	}
}

func TestDirectoryFor(t *testing.T) {
	cases := map[string]string{
		"Let's Encrypt":           "https://acme-v02.api.letsencrypt.org/directory",
		"(STAGING) Let's Encrypt": "https://acme-staging-v02.api.letsencrypt.org/directory",
		"Google Trust Services":   "https://dv.acme-v02.api.pki.goog/directory",
	}
	for org, want := range cases {
		_, got, ok := DirectoryFor(cert(org, 1))
		if !ok || got != want {
			t.Errorf("%s: got %q ok=%v", org, got, ok)
		}
	}
	if _, _, ok := DirectoryFor(cert("Sectigo Limited", 1)); ok {
		t.Error("Sectigo should not be auto-detected")
	}
}

func ca(t *testing.T, withARI bool, status int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/directory":
			d := map[string]string{"newOrder": srv.URL + "/new-order"}
			if withARI {
				d["renewalInfo"] = srv.URL + "/renewal-info/"
			}
			_ = json.NewEncoder(w).Encode(d)
		case strings.HasPrefix(r.URL.Path, "/renewal-info/"):
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			if r.URL.Path != "/renewal-info/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Retry-After", "21600")
			_, _ = w.Write([]byte(`{"suggestedWindow":{"start":"2026-11-02T17:18:36Z","end":"2026-11-04T12:29:25Z"},"explanationURL":"https://example.test/why"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLookupWindow(t *testing.T) {
	srv := ca(t, true, http.StatusOK)
	got := Lookup(context.Background(), cert("Whoever", 0x87654321), Options{Directory: srv.URL + "/directory"})
	if got.Status != "window" {
		t.Fatalf("status %s: %s", got.Status, got.Note)
	}
	if !got.WindowStart.Equal(time.Date(2026, 11, 2, 17, 18, 36, 0, time.UTC)) || got.RetryAfter != "21600" || got.ExplanationURL != "https://example.test/why" {
		t.Fatalf("unexpected %+v", got)
	}
}

func TestLookupUnsupported(t *testing.T) {
	srv := ca(t, false, http.StatusOK)
	got := Lookup(context.Background(), cert("x", 0x87654321), Options{Directory: srv.URL + "/directory"})
	if got.Status != "unsupported" {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupHTTPError(t *testing.T) {
	srv := ca(t, true, http.StatusInternalServerError)
	got := Lookup(context.Background(), cert("x", 0x87654321), Options{Directory: srv.URL + "/directory"})
	if got.Status != "error" || !strings.Contains(got.Note, "HTTP 500") {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupUnknownCA(t *testing.T) {
	got := Lookup(context.Background(), cert("Sectigo Limited", 1), Options{})
	if got.Status != "unknown-ca" || !strings.Contains(got.Note, "-ari-directory") {
		t.Fatalf("got %+v", got)
	}
}

// Package ari looks up a certificate's ACME Renewal Information (RFC 9773):
// the renewal window the issuing CA itself suggests.
//
// This is the one place renewhunt talks to an ACME CA, and only when you ask
// for it (-ari). It makes two unauthenticated, read-only GETs: the CA's
// directory and its renewalInfo resource for the certificate you probed. No
// account, no key, no order, nothing that can issue or revoke anything.
package ari

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Well-known ACME directories, keyed by the issuer organization of the leaf.
var knownDirectories = []struct {
	org, name, url string
}{
	{"(STAGING) Let's Encrypt", "Let's Encrypt staging", "https://acme-staging-v02.api.letsencrypt.org/directory"},
	{"Let's Encrypt", "Let's Encrypt", "https://acme-v02.api.letsencrypt.org/directory"},
	{"Google Trust Services", "Google Trust Services", "https://dv.acme-v02.api.pki.goog/directory"},
	{"ZeroSSL", "ZeroSSL", "https://acme.zerossl.com/v2/DV90"},
}

// Info is the outcome of one renewalInfo lookup.
type Info struct {
	CertID         string    `json:"cert_id,omitempty"`
	CA             string    `json:"ca,omitempty"`
	Directory      string    `json:"directory,omitempty"`
	WindowStart    time.Time `json:"window_start,omitempty"`
	WindowEnd      time.Time `json:"window_end,omitempty"`
	ExplanationURL string    `json:"explanation_url,omitempty"`
	RetryAfter     string    `json:"retry_after,omitempty"`
	// Status is one of: window, unsupported, unknown-ca, error.
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// Options controls a lookup.
type Options struct {
	// Directory overrides issuer-based CA detection.
	Directory string
	Client    *http.Client
	Timeout   time.Duration
}

// CertID returns the RFC 9773 unique identifier for a certificate:
// base64url(AKI keyIdentifier) "." base64url(DER serial number bytes).
func CertID(c *x509.Certificate) (string, error) {
	if len(c.AuthorityKeyId) == 0 {
		return "", errors.New("certificate has no Authority Key Identifier, so it has no ARI identifier")
	}
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return "", errors.New("certificate has no positive serial number")
	}
	serial := c.SerialNumber.Bytes()
	if serial[0]&0x80 != 0 {
		// DER INTEGER encoding keeps a leading zero so the value stays positive.
		serial = append([]byte{0}, serial...)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(c.AuthorityKeyId) + "." + enc.EncodeToString(serial), nil
}

// DirectoryFor guesses the ACME directory of the CA that issued c.
func DirectoryFor(c *x509.Certificate) (name, url string, ok bool) {
	orgs := strings.Join(c.Issuer.Organization, ", ")
	for _, k := range knownDirectories {
		if strings.EqualFold(orgs, k.org) || strings.HasPrefix(orgs, k.org) {
			return k.name, k.url, true
		}
	}
	return "", "", false
}

// Lookup fetches the CA's suggested renewal window for leaf.
func Lookup(ctx context.Context, leaf *x509.Certificate, opts Options) Info {
	var info Info
	id, err := CertID(leaf)
	if err != nil {
		info.Status, info.Note = "error", err.Error()
		return info
	}
	info.CertID = id
	info.Directory = opts.Directory
	if info.Directory == "" {
		name, url, ok := DirectoryFor(leaf)
		if !ok {
			org := strings.Join(leaf.Issuer.Organization, ", ")
			if org == "" {
				org = leaf.Issuer.CommonName
			}
			info.Status = "unknown-ca"
			info.Note = fmt.Sprintf("no known ACME directory for issuer %q; pass -ari-directory URL to check it", org)
			return info
		}
		info.CA, info.Directory = name, url
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if _, err := getJSON(ctx, client, info.Directory, &dir); err != nil {
		info.Status, info.Note = "error", "reading ACME directory: "+err.Error()
		return info
	}
	if dir.RenewalInfo == "" {
		info.Status = "unsupported"
		info.Note = "this CA's ACME directory does not advertise renewalInfo (no ARI); your client must pick its own renewal time"
		return info
	}
	var ri struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	hdr, err := getJSON(ctx, client, strings.TrimSuffix(dir.RenewalInfo, "/")+"/"+id, &ri)
	if err != nil {
		info.Status, info.Note = "error", "reading renewalInfo: "+err.Error()
		return info
	}
	if ri.SuggestedWindow.Start.IsZero() || ri.SuggestedWindow.End.IsZero() || ri.SuggestedWindow.End.Before(ri.SuggestedWindow.Start) {
		info.Status, info.Note = "error", "renewalInfo response has no valid suggestedWindow"
		return info
	}
	info.Status = "window"
	info.WindowStart = ri.SuggestedWindow.Start.UTC()
	info.WindowEnd = ri.SuggestedWindow.End.UTC()
	info.ExplanationURL = ri.ExplanationURL
	info.RetryAfter = hdr.Get("Retry-After")
	return info
}

func getJSON(ctx context.Context, c *http.Client, url string, v any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "renewhunt (+https://github.com/Blackman99/renewhunt)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", url, err)
	}
	return resp.Header, nil
}

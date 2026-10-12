// Package clients probes local ACME client presence and versions (optional).
package clients

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Info describes one detected client.
type Info struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Version string `json:"version,omitempty"`
	Note    string `json:"note,omitempty"`
	ARI     string `json:"ari,omitempty"`
}

// Probe looks for certbot, acme.sh, lego, and cert-manager CRDs (via kubectl).
func Probe() []Info {
	return []Info{
		probeCertbot(),
		probeAcmeSh(),
		probeLego(),
		probeCertManager(),
	}
}

func probeCertbot() Info {
	info := Info{Name: "certbot"}
	out, err := exec.Command("certbot", "--version").CombinedOutput()
	if err != nil {
		info.Note = "not found on PATH (skipped)"
		return info
	}
	info.Found = true
	ver := strings.TrimSpace(string(out))
	info.Version = ver
	// certbot 1.x / 2.x print "certbot 2.11.0" etc.
	re := regexp.MustCompile(`(\d+)\.(\d+)`)
	m := re.FindStringSubmatch(ver)
	if len(m) >= 3 {
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		if maj < 4 {
			info.Note = "certbot <4.0 renews at a fixed ~30 days before expiry; prefer ≥4.0 (⅓ of lifetime) for short certs"
		} else {
			info.Note = "certbot ≥4.0 uses ~⅓ of lifetime — good for 64-day / 45-day profiles"
		}
		if maj > 4 || (maj == 4 && min >= 1) {
			info.ARI = "Certbot 4.1+ supports ARI — best path for LE short lifetimes"
		} else {
			info.ARI = "upgrade to Certbot 4.1+ for ARI (ACME Renewal Information)"
		}
	}
	return info
}

func probeAcmeSh() Info {
	info := Info{Name: "acme.sh"}
	candidates := []string{"acme.sh"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home+"/.acme.sh/acme.sh")
	}
	candidates = append(candidates, "/root/.acme.sh/acme.sh")
	for _, c := range candidates {
		out, err := exec.Command(c, "--version").CombinedOutput()
		if err != nil {
			continue
		}
		info.Found = true
		info.Version = strings.TrimSpace(string(out))
		info.Note = "check --days / --renew-days; prefer default relative behaviour or ARI if available"
		info.ARI = "confirm your acme.sh build supports ARI; avoid hardcoded --days 80/60"
		return info
	}
	info.Note = "not found (skipped)"
	return info
}

func probeLego() Info {
	info := Info{Name: "lego"}
	out, err := exec.Command("lego", "--version").CombinedOutput()
	if err != nil {
		info.Note = "not found on PATH (skipped)"
		return info
	}
	info.Found = true
	info.Version = strings.TrimSpace(string(out))
	info.Note = "lego renew uses days-before-expiry; keep the window under ~21d for 64-day certs or use ARI"
	info.ARI = "check lego release notes for ARI support"
	return info
}

func probeCertManager() Info {
	info := Info{Name: "cert-manager"}
	out, err := exec.Command("kubectl", "api-resources", "--api-group=cert-manager.io").CombinedOutput()
	if err != nil {
		info.Note = "kubectl missing or no cluster (skipped)"
		return info
	}
	s := string(out)
	if !strings.Contains(s, "certificates") && !strings.Contains(s, "Certificate") {
		info.Note = "cert-manager CRDs not present in current context"
		return info
	}
	info.Found = true
	info.Version = "CRDs present"
	info.Note = "prefer renewBeforePercentage over absolute renewBefore hours; 720h (30d) breaks on 64-day/45-day certs"
	info.ARI = "cert-manager supports ARI in recent versions — enable it when available"
	return info
}

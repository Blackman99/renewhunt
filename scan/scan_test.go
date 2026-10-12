package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyStandalone(t *testing.T) {
	cases := []struct {
		n    int
		want Severity
	}{
		{83, Blocked},
		{80, Blocked},
		{60, Risky},
		{30, Info},
	}
	for _, c := range cases {
		got, _, _ := classifyStandalone(c.n)
		if got != c.want {
			t.Fatalf("day %d: got %s want %s", c.n, got, c.want)
		}
	}
}

func TestClassifyRenewBeforeHours(t *testing.T) {
	sev, _, _ := classify("renew_before_hours", 2160, "renewBefore: 2160h") // 90d
	if sev != Blocked {
		t.Fatalf("2160h: got %s want BLOCKED", sev)
	}
	sev, _, _ = classify("renew_before_hours", 720, "renewBefore: 720h")
	if sev != Risky {
		t.Fatalf("720h: got %s want RISKY", sev)
	}
	sev, _, _ = classify("renew_before_hours", 336, "renewBefore: 336h") // 14d
	if sev != OK {
		t.Fatalf("336h: got %s want OK", sev)
	}
}

func TestClassifyDaysBeforeExpiry(t *testing.T) {
	sev, _, _ := classifyDaysBeforeExpiry(80)
	if sev != Blocked {
		t.Fatalf("80d before: got %s", sev)
	}
	sev, _, _ = classifyDaysBeforeExpiry(21)
	if sev != OK {
		t.Fatalf("21d before: got %s want OK", sev)
	}
}

func TestScanFixtures(t *testing.T) {
	root := filepath.Join("..", "testdata")
	if _, err := os.Stat(root); err != nil {
		t.Skip("testdata missing")
	}
	res, err := Scan([]string{root}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned == 0 {
		t.Fatal("expected to scan fixtures")
	}
	var blocked, risky int
	for _, f := range res.Findings {
		switch f.Severity {
		case Blocked:
			blocked++
		case Risky:
			risky++
		}
	}
	if blocked == 0 {
		t.Fatalf("expected BLOCKED findings in bad fixtures, got %#v", res.Findings)
	}
	if risky == 0 {
		t.Fatalf("expected RISKY findings, got %#v", res.Findings)
	}
	t.Logf("findings: blocked=%d risky=%d scanned=%d", blocked, risky, res.Scanned)
}

func TestMatchLineCertbotDays(t *testing.T) {
	fs := matchLine("cron", 1, "0 3 * * * certbot renew --days 80 --quiet")
	if len(fs) == 0 {
		t.Fatal("expected hit")
	}
	if fs[0].Severity != Blocked {
		t.Fatalf("got %s", fs[0].Severity)
	}
}

func TestMatchLineRenewBefore(t *testing.T) {
	fs := matchLine("c.yaml", 1, "  renewBefore: 720h")
	if len(fs) == 0 {
		t.Fatal("expected hit")
	}
	if fs[0].Severity != Risky {
		t.Fatalf("got %s want RISKY", fs[0].Severity)
	}
}

func TestMatchLineSkipsComments(t *testing.T) {
	fs := matchLine("cron", 1, "# BAD: hardcoded --days 80")
	if len(fs) != 0 {
		t.Fatalf("comment should be skipped: %#v", fs)
	}
}

func TestMatchLineGoodPercentSkipped(t *testing.T) {
	fs := matchLine("c.yaml", 1, "  renewBeforePercentage: 33")
	for _, f := range fs {
		if f.Severity == Blocked {
			t.Fatalf("unexpected BLOCKED on percentage: %#v", f)
		}
	}
}

# Changelog

## Unreleased

### Added
- `renewhunt live -ari host…` (and `-ari` with `-check-live`) asks the issuing CA for each served certificate's ARI renewal window (RFC 9773) and prints an ARI table with the window and how far away it is. JSON results gain an `"ari"` object (`cert_id`, `ca`, `directory`, `window_start`, `window_end`, `explanation_url`, `retry_after`, `status`).
- ARI judging: still served after the CA's window closed is RISKY; a window the CA moved before half the lifetime (usually a mass revocation) is RISKY, and BLOCKED once that window has passed.
- CA detection from the issuer for Let's Encrypt (production and staging), Google Trust Services and ZeroSSL; `-ari-directory URL` points at any other ACME directory. ARI is off by default and is two unauthenticated, read-only GETs per host.
- Homebrew install: `brew install Blackman99/tap/renewhunt` (macOS and Linux, amd64/arm64). Each release now updates `Formula/renewhunt.rb` in [Blackman99/homebrew-tap](https://github.com/Blackman99/homebrew-tap) automatically.

## v0.2.0 — 2026-10-19

### Added
- `renewhunt live host[:port]…` probes the certificate each host actually serves and reports lifetime, percent used, days left, issuer, and chain validity. Certificates past ~80% of their lifetime are RISKY (renewal is late, failing, or not reloaded); expired or under 7 days left is BLOCKED. Only the named hosts are contacted, never an ACME CA.
- `-check-live host1,host2` on the default command adds the live section to the combined report and JSON (`"live"` key); `-timeout` sets the per-host timeout.
- cert-manager `renewBefore` findings that are RISKY or BLOCKED now carry `"suggestion": "renewBeforePercentage: 33"`, printed as a `fix:` line in the table.
- `renewBeforePercentage` values are classified (15–50 OK, under 15 RISKY, over 50 INFO, outside (0,100) BLOCKED).

### Fixed
- `renewBefore: 720h0m0s` (the form `kubectl get -o yaml` prints) and other Go durations such as `43200m` or quoted `"2160h"` were silently missed.
- Table output truncated multi-byte characters (`⅔`, `≈`) mid-rune; truncation is now rune-aware.
- File paths under the working directory print relative instead of absolute.

## v0.1.0 — 2026-10-12

- First release: `scan`, `clients`, `timers`, default combined run, `-json`, `-system`, exit 1 on BLOCKED.

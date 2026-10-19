# Changelog

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

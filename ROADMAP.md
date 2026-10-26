# Roadmap

## v0.1 (shipped)

- `renewhunt scan` — hunt hardcoded renewal day windows in files
- `renewhunt clients` — detect certbot / acme.sh / lego / cert-manager presence
- `renewhunt timers` — list systemd timers and crontab renew lines
- Default command runs scan + clients + timers; exit 1 on any BLOCKED
- Human table + `--json`
- Fixture corpus under `testdata/` + unit tests + CI e2e

## v0.2 (shipped 2026-10-19)

- `renewhunt live host…` and `-check-live` — live expiry / renewal-timing probe for hosts you name
- Suggest `renewBeforePercentage: 33` for cert-manager `renewBefore` hits; classify existing `renewBeforePercentage`
- Parse cert-manager Go durations (`720h0m0s`, `43200m`, quoted values)

## v0.2.x

- ✅ Homebrew formula — `brew install Blackman99/tap/renewhunt`, auto-updated on each release

## v0.3

- ✅ ARI (ACME Renewal Information, RFC 9773) probe — `renewhunt live -ari host…` shows the CA's suggested renewal window and flags missed or revocation-driven early windows
- Richer cert-manager / Traefik / Caddy config parsers

# Roadmap

## v0.1 (shipped)

- `renewhunt scan` — hunt hardcoded renewal day windows in files
- `renewhunt clients` — detect certbot / acme.sh / lego / cert-manager presence
- `renewhunt timers` — list systemd timers and crontab renew lines
- Default command runs scan + clients + timers; exit 1 on any BLOCKED
- Human table + `--json`
- Fixture corpus under `testdata/` + unit tests + CI e2e

## v0.2

- Live expiry probe (`--check-live`) for hosts you name
- Suggest `renewBeforePercentage` for cert-manager Certificate resources
- Homebrew formula

## v0.3

- ARI (ACME Renewal Information) endpoint probe
- Richer cert-manager / Traefik / Caddy config parsers

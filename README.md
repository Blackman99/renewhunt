<p align="center"><img src="site/logo-512.png" width="120" alt="renewhunt logo"></p>

# renewhunt

**Will your ACME renewal survive Let's Encrypt's 64-day (then 45-day) certificates?**

On 2026-10-07 Let's Encrypt announced 64-day certificates ([blog](https://letsencrypt.org/2026/10/07/64-day-certs)): staging starts **2026-10-14**, production **2027-02-10**, then 45-day later. They told operators to *“Grep for common hardcoded numbers like 83, 80 or 60 in cron jobs, wrapper scripts and runbooks.”* renewhunt does that hunt for you — plus classifies each hit, checks ACME client / ARI readiness, and lists renew timers.

Distinct from [certfan](https://github.com/Blackman99/certfan) (live multi-IP TLS sameness): renewhunt audits **renewal automation config**, not live endpoints.

![demo](site/demo.gif)

Landing: https://blackman99.github.io/renewhunt/ · Docs: https://blackman99.github.io/renewhunt/docs/

## Install

```bash
brew install Blackman99/tap/renewhunt   # macOS / Linux (Homebrew)
go install github.com/Blackman99/renewhunt/cmd/renewhunt@latest
```

Or download a static binary for linux / macOS / windows from [Releases](https://github.com/Blackman99/renewhunt/releases).

## Usage

```console
$ renewhunt scan ./testdata
SCAN  files=7 skipped=0 findings=6 worst=BLOCKED
SEV      FILE:LINE                                      MATCH                 REASON
BLOCKED  testdata/bad/cron-certbot-days80:2             --days 80             …
BLOCKED  testdata/bad/renew-script.sh:3                 83                    …
BLOCKED  testdata/cert-manager/certificate-720h.yaml:14 renewBefore: 720h     …
$ echo $?
1
```

cert-manager hits come with a drop-in fix:

```console
RISKY  deploy/cert.yaml:15  renewBefore: 720h0m0s           renewBefore 720h (≈30.0d) is an absolute window…
                            fix: renewBeforePercentage: 33  (cert-manager ≥ v1.16; or delete renewBefore …)
```

Check what your servers actually serve, not just what the config says:

```console
$ renewhunt live letsencrypt.org expired.badssl.com
LIVE  hosts=2 worst=BLOCKED
SEV      HOST                LIFETIME  USED  LEFT     ISSUER             REASON
INFO     letsencrypt.org     90d       50%   45.5d    Let's Encrypt      90-day era certificate, fine today; …
BLOCKED  expired.badssl.com  4d        100%  expired  COMODO CA Limited  certificate expired 4207.1d ago — …
```

Ask the CA itself when it wants each certificate renewed, via ARI (ACME Renewal Information, [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)):

```console
$ renewhunt live -ari letsencrypt.org valid-isrgrootx1.letsencrypt.org
LIVE  hosts=2 worst=INFO
SEV   HOST                              LIFETIME  USED  LEFT   ISSUER         REASON
INFO  letsencrypt.org                   90d       57%   38.5d  Let's Encrypt  90-day era certificate, fine today; Let's Encrypt production moves to 64-day on 2027-02-10
INFO  valid-isrgrootx1.letsencrypt.org  90d       5%    85.6d  Let's Encrypt  90-day era certificate, fine today; Let's Encrypt production moves to 64-day on 2027-02-10

ARI   (renewal windows suggested by the issuing CA, RFC 9773)
HOST                              CA             WINDOW (UTC)                         WHEN      NOTE
letsencrypt.org                   Let's Encrypt  2026-11-02 17:18 – 2026-11-04 12:29  in 7.6d
valid-isrgrootx1.letsencrypt.org  Let's Encrypt  2026-12-19 20:22 – 2026-12-21 15:33  in 54.7d
```

`-ari` adds two read-only GETs per host to the issuing CA (its ACME directory and the certificate's `renewalInfo`); no account, no key. Let's Encrypt (prod and staging), Google Trust Services and ZeroSSL are detected from the issuer; for any other ACME CA pass `-ari-directory https://…/directory`. A host still served after the CA's window closed is **RISKY**, and a window the CA moved early (usually a revocation) is **RISKY**, or **BLOCKED** once it has passed.

`renewhunt` (no subcommand) runs scan + clients + timers; add `-check-live host1,host2` to include live probes. Add `-system` to also walk `/etc/letsencrypt`, cron, and systemd unit dirs. Use `-json` for scripts. Exit `1` if any finding is **BLOCKED**.

Read-only. No network required for scan; `live` only connects to the hosts you name, and talks to a CA only when you add `-ari`.

See [GOAL.md](GOAL.md), [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.

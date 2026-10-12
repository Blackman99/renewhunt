# Goal

**Tell you, in one command, whether your ACME renewal setup will survive Let's Encrypt's move to 64-day (then 45-day) certificates — by hunting hardcoded day counts, checking ACME client/ARI readiness, and flagging absolute renewBefore windows that break on short lifetimes.**

In scope: read-only scan of configs/scripts/cron/systemd for hardcoded renewal day windows (83/80/60/30 and common renew-before patterns), classification against LE's 64-day and 45-day profiles, optional ACME client version probes, systemd timer / crontab listing, human + JSON output.

Out of scope: renewing certificates, talking to ACME CAs at runtime (live expiry probe is roadmap), rewriting configs for you, general TLS endpoint consistency (that is certfan), certificate issuance.

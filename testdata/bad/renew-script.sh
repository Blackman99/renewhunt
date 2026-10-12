#!/usr/bin/env bash
# Hunt target: renew when age hits classic 90-day windows
RENEW_DAYS=83
if [[ "$AGE_DAYS" -ge 83 ]]; then
  certbot renew --force-renewal
fi
# classic 60-day window (days before expiry)
renew_before_expiry=60

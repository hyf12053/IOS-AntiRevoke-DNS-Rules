# Architecture

## Data flow

```text
Apple official host tables
            |
            v
 normalized candidate domains
            |
            +-----------------------------+
            |                             |
            v                             v
 normal endpoint group             enhanced endpoint
 - Khoindvn                        - Sideloading afterinstalling
 - AppleJr
 - Sideloading whileinstalling
            |                             |
            v                             v
 normal target union              enhanced endpoint targets
            |                             |
            |              extra = enhanced - normal
            |                             |
            +---------------+-------------+
                            |
             +--------------+--------------+
             |                             |
             v                             v
 output/ normal artifacts       output/enhanced/ artifacts
 - normal proxy rules           - proxy rules: extra only
 - normal iOS profile           - iOS profile: normal + extra
```

Selected DNS payloads with a non-empty domain list in `DNSSettings.SupplementalMatchDomains` contribute those domains directly to their normal or enhanced result set. Their URLs are not queried, even if present. Lists are normalized and deduplicated; domains outside Apple's candidate tables are retained. Empty, catch-all, and invalid entries are ignored. Domain names in web clips, server addresses, or on-demand connection exceptions are not treated as target lists.

Payloads without an explicit domain list use the probing flow above. All NXDOMAIN or empty answers are checked against a public reference DoH resolver. A probed domain is published only when the upstream answer differs from a valid public answer, or when the upstream returns a non-global address such as `0.0.0.0`.

## Endpoint selection

The three mobileconfig files are downloaded and decoded on every run. Endpoint URLs are never hardcoded as runtime inputs; payload identifiers select the intended mode from the current profile.

| Source | Role | Selection |
| --- | --- | --- |
| Khoindvn | Normal | First DNS payload with explicit domains or a valid HTTPS endpoint |
| AppleJr | Normal | First DNS payload with explicit domains or a valid HTTPS endpoint |
| Sideloading | Normal | `novadev.nexdns.whileinstalling` |
| Sideloading | Enhanced | `novadev.nexdns.afterinstalling` |

The enhanced endpoint is intentionally excluded from the normal endpoint union. Its contribution is calculated independently so proxy users can toggle the enhanced rule set without duplicating normal rules.

## Components

`utils/scraper.py`

- Downloads Apple host data and all required source profiles.
- Extracts domains only from recognized `Host` or `主机` tables.
- Resolves page XPaths to the current mobileconfig download URLs.
- Fails when a required page, link, or profile cannot be retrieved.

`utils/crypto_handler.py`

- Parses unsigned plist profiles or verifies CMS-signed DER mobileconfig files.
- Extracts HTTPS DNS endpoints, explicit match-domain lists, and payload identifiers.
- Creates separately named normal and enhanced iOS profiles.
- Signs generated profiles with the configured certificate chain.

`utils/dns_probe.py`

- Sends RFC 8484 A and AAAA queries using DNS wire format over HTTPS.
- Skips upstream and reference queries for payloads with explicit domain lists and merges their domains with probed results, preserving source attribution.
- Treats non-global addresses as explicit filtering results.
- Uses the reference resolver to distinguish filtering from legitimate NODATA or NXDOMAIN.
- Rejects partial output when any required query fails after retries.

`utils/rule_converter.py`

- Preserves the existing normal filenames.
- Supports an independent output directory, filename prefix, and domain-list name for enhanced rules.

`main.py`

- Selects normal and enhanced payloads from the decoded profiles.
- Runs normal and enhanced discovery independently.
- Filters the **normal** report first (`_filter_normal_report`), removing
  install-verification domains so apps can be installed. Domains that are only
  unsafe *while installing* are returned separately as deferred domains instead
  of being discarded.
- Computes `enhanced extra = enhanced endpoint targets - filtered normal targets`,
  then re-adds the deferred domains so they reach the enhanced outputs.
- Generates normal rules from normal targets.
- Generates enhanced proxy rules from enhanced extras only.
- Generates the enhanced iOS profile from `normal targets + enhanced extras`.

Ordering matters here. Computing the enhanced extra set before filtering normal
would leave a deferred domain absent from normal *and* absent from the enhanced
outputs, silently removing it from the rule files as well. The filter therefore
runs first, and `_filter_enhanced_sets` re-adds the deferred domains explicitly
rather than relying on the enhanced endpoint to rediscover them (it usually
returns only the canonical host and not the CNAME variants).

## Output contract

`output/` contains the backward-compatible normal files and root metadata.

`output/enhanced/` contains:

- `RevokeGuard_Enhanced.mobileconfig`: merged normal and enhanced domains.
- `RevokeGuard_Enhanced_*.txt`: enhanced extra domains only.
- `enhanced-domains.txt`: plain enhanced extra-domain list.
- `metadata.json`: enhanced endpoint, extra-domain count, and merged profile count.

## Safety gates

- All three source profiles are required.
- Both Sideloading payload identifiers must exist.
- Apple must yield at least 100 candidate domains.
- Normal and enhanced target sets must each remain below 50% of candidates.
- The normal target set must not fall below `MIN_TARGET_DOMAINS` (10). Every
  healthy value in this repository's history is 13-34; the two known
  degradations were 7 and 8. Without this floor a silent collapse publishes as a
  normal update — on 2026-09-11 the list dropped 12 → 7 and stayed there for six
  days, losing every DigiCert OCSP/CRL host, with no failing run to notice it.
  The floor deliberately does **not** apply to the enhanced endpoint, which
  legitimately reports only ~8 targets (6 surviving as extras).
- The normal set is validated **again after filtering**. Filtering can empty it
  (on 2026-09-11 six of the seven survivors were exclusion-listed), and an empty
  `SupplementalMatchDomains` array still produces a non-empty file, so the ratio
  gate, the workflow's `test -s` checks and `check_profile_contract.py` would all
  pass a profile that matches no domains at all.
- Every DNS query must complete after retries.
- Normal discovery and enhanced endpoint discovery must both produce targets.
- All normal and enhanced artifacts must be generated.
- No published profile may contain an install-verification domain
  (`ppq.*`, `appattest.apple.com`, `vpp.itunes.apple.com`). The workflow decodes
  each profile — signed or unsigned — and fails the run on a match.
- Signing is refused when the certificate is expired or not yet valid.
- GitHub Actions verifies the CMS signature only for runs that actually signed;
  a fork without `SSL_CERT` / `SSL_KEY` publishes unsigned profiles instead of
  failing.

## Metadata

Root `output/metadata.json` uses schema version 3 and records:

- Apple source and candidate count.
- Every discovered profile endpoint.
- Each payload's normalized `domains` list (empty for payloads requiring probing).
- Selected normal endpoints and the enhanced endpoint.
- Normal discovery details, including `profile_domains` counts for sources used directly without probing.
- Enhanced endpoint targets, additional domains, and merged profile count.
- Normal and enhanced artifact paths.

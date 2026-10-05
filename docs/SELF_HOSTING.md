# Self-hosting the DoH backend | 自建 DoH 后端

The generated profiles point at a DNS-over-HTTPS resolver. By default that is
upstream's `reject.rzmy.dpdns.org`, which means your profiles depend on someone
else's server staying up and on their domain staying registered.

This guide replaces that dependency with a Worker you control. There are two
routes; neither requires buying anything.

---

## First, what DigitalPlat FreeDomain does and does not do

[DigitalPlat FreeDomain](https://github.com/DigitalPlatDev/FreeDomain) is a
**domain registrar**, not a DNS service. Its own documentation is explicit:

> DigitalPlat delegates registered domains to external authoritative
> nameservers. It does not provide an ordinary DNS record editor.
> — [What DigitalPlat Does](https://github.com/DigitalPlatDev/FreeDomain/blob/main/documents/tutorial/platform/1.0-product-boundaries.md)

So registering `yourname.dpdns.org` there gets you a name and a place to enter
**nameservers**. It does not get you a resolver, and it does not host your
records. To use such a domain you still need a DNS provider (Cloudflare, or
self-hosted authoritative DNS) to hold the zone.

That is why the reverse-engineered `reject.rzmy.dpdns.org` exists: `rzmy.dpdns.org`
is a FreeDomain name whose nameservers point at Cloudflare
(`daisy.ns.cloudflare.com`), and a record inside that zone points at the
Worker.

**The good news**: a free `*.workers.dev` hostname already comes with its own
valid TLS certificate, so you can skip the registrar entirely. Apple only
requires that `ServerURL` uses `https://` and that the hostname matches the
certificate; it never requires you to own the domain.

| Route | Cost | Needs a domain? | Custom hostname |
| --- | --- | --- | --- |
| **A. workers.dev** (recommended) | free | no | `rg.<you>.workers.dev` |
| **B. FreeDomain + Cloudflare** | free | yes, free | `reject.<you>.dpdns.org` |

---

## Route A — Cloudflare Worker on `workers.dev`

### 1. Install Wrangler and sign in

```bash
npm install -g wrangler
wrangler login
```

### 2. Deploy

From the repository root:

```bash
cd worker
wrangler deploy
```

No `npm install` is needed: the Worker has no runtime dependencies, and the
globally installed Wrangler bundles it on its own. (Wrangler may warn that
`esbuild` and `workerd` have install scripts it did not run — that warning does
not affect bundling.)

Wrangler prints the deployed URL, e.g.
`https://rg.yourname.workers.dev`. Verify it:

```bash
curl "https://rg.yourname.workers.dev/health"
# {"status":"ok","role":"anti-revoke DoH sinkhole","allowlist":[]}
```

### 3. Confirm it refuses everything

```bash
# Expect NXDOMAIN, which curl reports as "Non-existent domain"
curl -H 'accept: application/dns-message' \
  "https://rg.yourname.workers.dev/dns-query?dns=$(printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ppq\x05apple\x03com\x00\x00\x01\x00\x01' | base64 -w0 | tr '+/' '-_' | tr -d '=')"
```

### 4. Point the profiles at it

Set the URL as a **repository variable** named `BACKEND_HOST`
(Settings → Secrets and variables → Actions → Variables → New repository
variable). The value is the full Worker URL:

```
https://rg.yourname.workers.dev
```

A full URL is accepted, not just a bare hostname, precisely because Workers are
not served from the root of a domain. Adding `/dns-query` yourself is fine too —
either form works.

Then re-run the workflow. The generated profile will carry your URL as
`ServerURL`.

### 5. Point your device at the new profile

Re-generating the profile is not enough on its own: the device keeps using the
installed profile until you install the new one. Install it, then **remove the
old profile** — otherwise two DNS payloads with different servers coexist.

### 6. Short download links (optional, recommended)

The Worker also serves the two profiles, so you can hand out short links
instead of the long `raw.githubusercontent.com` paths:

| Link | Serves |
| --- | --- |
| `https://rg.yourname.workers.dev/download` | normal profile |
| `https://rg.yourname.workers.dev/download2` | enhanced profile |

The names match upstream's `/download` and `/download2`, so existing
instructions keep working.

This is not only cosmetic. `raw.githubusercontent.com` serves `.mobileconfig`
as `Content-Type: text/plain` together with
`X-Content-Type-Options: nosniff`, which forbids the system from sniffing the
real type. Safari tolerates that when the user taps the file directly, but iOS
identifies a configuration profile by
`Content-Type: application/x-apple-aspen-config`, and other entry points (an
in-app link, a redirect, a QR scan) may refuse a `text/plain` response. These
routes send the correct type.

Verify both:

```bash
curl -sI "https://rg.yourname.workers.dev/download" | grep -i content-type
# content-type: application/x-apple-aspen-config
```

**Failure behaviour is deliberate.** The profile is fetched from GitHub at
request time, so a bad day upstream could return an HTML error page or a
truncated body with HTTP 200. Forwarding that would make the device install a
broken profile while looking like a successful download. Instead the Worker
validates the body (DER `0x30` for signed profiles, `<?xml` for unsigned ones,
no HTML, minimum length) and answers **502** if it does not look like a
profile. A 502 is visible and diagnosable; a silently broken profile is not.

Change `RAW_BASE` in `wrangler.toml` if you serve the files from a different
repository or branch.

---

## Route B — FreeDomain name in front of the Worker

Only worth it if you want a recognisable hostname. Steps:

1. Register at <https://dash.domain.digitalplat.org/> (1 domain per account).
2. Add the domain to Cloudflare (*Add a site*), pick the free plan.
3. Cloudflare shows two nameservers. Enter **both** in the DigitalPlat panel,
   exactly as given — hostnames, never IP addresses.
4. Wait for Cloudflare to report the zone as active, then open
   **Workers & Pages → your worker → Settings → Domains & Routes → Add →
   Custom Domain** and enter e.g. `doh.yourname.dpdns.org`.

   The DNS record is created automatically. Do **not** add it yourself as an
   A/CNAME record — a proxied record pointing at arbitrary infrastructure does
   not route to the Worker.
5. Set `BACKEND_HOST=https://doh.yourname.dpdns.org`.

`dpdns.org` is on the [Public Suffix List](https://publicsuffix.org/), which is
what lets Cloudflare treat `yourname.dpdns.org` as a registrable zone rather
than a subdomain of someone else's site. (The list has it in the *private*
section — the same section `github.io` uses — so each registration is a separate
site.)

---

## Why "block everything" is correct here

The Worker answers NXDOMAIN unconditionally. That looks reckless, so the
reasoning is worth stating: `SupplementalMatchDomains` is a **match** list.
Apple's own schema:

> A list of domain strings used to determine which DNS queries use the DNS
> server. If not set, all domains use the DNS server.
> — [com.apple.dnsSettings.managed](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsSettings.managed.yaml)

The device therefore only sends the hostnames listed in the profile. Nothing
else on the device reaches this server, so there is no "too much blocking"
surface to worry about.

This differs deliberately from the NexDNS-style backends, which are *routing
tables* into a policy resolver that still resolves allowlisted names. Two
consequences:

- **Good**: the profile's domain list stays the single source of truth. There is
  no second list on the server that can drift out of sync with it.
- **Cost**: if a blocked suffix also contains a hostname that *must* resolve,
  nothing here can rescue it — the fix has to happen in the profile's exclusion
  lists (which is what `main.py` does for `appattest.apple.com`).

The `ALLOWLIST` variable exists for the rare case where the profile genuinely
must block a suffix except for one name inside it:

```bash
cd worker
npx wrangler secret put ALLOWLIST     # or: [vars] in wrangler.toml
# e.g. register.appattest.apple.com
```

Allowlisted names are forwarded to Cloudflare DNS and resolve normally. An entry
covers its subdomains. Prefer fixing the profile's exclusion list; treat this as
a safety valve, because anything here is invisible when you read the profile.

---

## Tests

```bash
cd worker
npm test        # 23 wire-format tests, no dependencies
```

The wire format is where a DoH sinkhole fails silently: a malformed reply does
not raise an error on the device, the names simply fail to resolve, which is
indistinguishable from the behaviour you were trying to produce. The suite
covers query parsing (including compression-pointer and truncated-label
rejection), header construction, the allowlist boundary, and GET/POST handling.

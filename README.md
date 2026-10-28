# waf

[![CI](https://github.com/openasy/waf/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/waf/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) WAF product: **attacks on your web applications blocked at the door, until
the code is fixed** (ADR 0069). WAF stands in front of your sites and puts every request through
[Coraza](https://coraza.io/) with the [OWASP Core Rule Set](https://coreruleset.org/) before it reaches the
application. It manages the sites, the rule set's paranoia level and threshold, exclusions for false positives and
rules of your own, such as virtual patches for flaws DAST found, and shows what was blocked, by which rule and why.

```
browser ──TLS──▶ your TLS proxy ──▶ waf :8000  Coraza + OWASP CRS ──allowed──▶ the application
                                       │  blocked: 403 with a reference
                                       ▼
                                    waf :8080  sites, rules, exclusions, Traffic, Blocked
```

Coraza runs in a small Go proxy inside the same container (`proxy/`), started and watched by the application. It holds
no settings of its own: the application writes each site's SecLang to a file on a tmpfs and sends SIGHUP, and the proxy
reports what it matched as JSON lines.

## Sites

- **A site** is its host names (`shop.example.com`, or `*` for every host no other site has) and the application
  behind it (`http://shop:3000`). Requests for a host no site has get 404. The application sees the host name people
  asked for, and `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto`.
- **New sites start in detection-only mode**: every rule runs and what matched is reported as "would block", but
  nothing is refused, so turning WAF on cannot break an application. Read Blocked for a while, add exclusions for the
  false positives, then switch the site to Block; the switch shows how many requests it would have blocked in the last
  7 days first.
- **The rule set** runs per site: paranoia level 1 to 4 (1 by default), the inbound anomaly score at which a request is
  blocked (5 by default, one critical match), and groups turned off for a stack the site does not run, such as PHP.
  Responses are passed on as they come; the rule set's response rules (data leakages) do not run yet.
- **Requests a rule matched** are kept with the rules, the anomaly score, the client, the path and the query. Values of
  parameters, cookies and headers whose names look like a secret (password, token, session, key and the like) are not
  kept, only their length: a password with a quote in it matches the SQL injection rules, and every viewer reads
  Blocked. Request bodies and headers are not kept.
- **A blocked client** gets 403 and a reference, the id of the event, which finds it on Blocked and in search.

## Tuning

- **Exclusions** leave a rule, a range of rules or one part of the request (`ARGS:filter`,
  `REQUEST_HEADERS:User-Agent`) out for one site, everywhere or under one path, with a reason. Blocked offers one for
  each rule a request matched.
- **Custom rules** are SecLang, for one site or every site, after the rule set: `SecRule` and `SecAction` only, ids from
  1000000 to 1999999, phase 1 or 2. Operators that read files, look up DNS or run scripts, and the actions `ctl`, `exec`,
  `setenv`, `allow` and `redirect`, are refused, so a rule can match and refuse requests but not reach the disk or turn
  the engine off. Coraza compiles each rule before it is kept, and its error is shown.
- **Virtual patches**: the custom rule editor writes a rule for one kind of attack (SQL injection, cross-site scripting,
  path traversal, anything but a number) in one parameter of one page, for a DAST finding, until the code is fixed.

Every change is served within a second. When the proxy does not take a change, the rules before it keep serving and
the screens say why.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs waf | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/. Then point your TLS proxy at port
8000 for the sites' host names, in place of the applications, and set `OPENASY_TRUSTED_PROXIES` to its address:

```
# Caddyfile
shop.example.com {
	reverse_proxy waf:8000
}
```

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | UI and API |
| `WAF_PROXY_PORT` | `8000` | The sites |
| `WAF_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_TRUSTED_PROXIES` | | Addresses or CIDRs whose `X-Forwarded-For` names the client, such as your TLS proxy. None by default (ADR 0026) |
| `OPENASY_PRODUCTS` | | The install's OpenAsy products, for the product switcher |
| `WAF_RETENTION_DAYS` | `30` | How long matched requests and traffic counts are kept |
| `WAF_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `WAF_DATA` | `/data` | The SQLite file |
| `WAF_RUN_DIR` | `/tmp/waf` | The proxy's config; keep it on a tmpfs |
| `WAF_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `WAF_HEADLESS` | `false` | `true` serves only the API |
| `WAF_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_waf_engine_up`, `openasy_waf_requests_total{site}`,
`openasy_waf_matched_requests_total{site,action}`, `openasy_waf_upstream_errors_total{site}` and
`openasy_waf_events_dropped_total`. Watch `openasy_waf_engine_up` from a system other than WAF: while the proxy is down,
the sites do not answer. At most 500 matched requests a second are kept; the rest are counted, still blocked, and
dropped.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`. Coraza reads
only the rule set built into the proxy and the SecLang the application writes; request bodies it buffers go to `/tmp`.
Bodies over 13 MiB are refused on sites that block.

## Roles

Viewers see everything; editors also add exclusions and custom rules; admins also add, change and delete sites and
switch their mode, and manage members and API tokens (ADR 0003).

## Not yet

Rules made from DAST findings by linking to DAST (the virtual patch is written by hand from the finding for now),
inspecting responses, blocking addresses for a while and threat-intel lists, rate limits, the rule set's updates
without a new release, testing a rule against past traffic, hits per exclusion, TLS in the proxy itself (it sits behind
the install's TLS proxy, ADR 0026), load balancing between several upstreams, and sending blocked attacks to SIEM are
planned.

## Develop

```bash
npm install
npm test        # builds proxy/ with the pinned Go into vendor/, then sends attacks through it to a local test backend, and checks every API response against openapi.json
npm run dev     # the UI, with the API on :8080
node scripts/openapi.ts   # after changing the API
```

## Licence

AGPL-3.0 (ADR 0008). Coraza and the OWASP Core Rule Set are Apache-2.0.

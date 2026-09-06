# Operator configuration

WPShield ships with placeholder hostnames. Real deployment values must never reach the public
repository, because a hostname-to-backend map tells an attacker which sites share a machine, which
internal ports they listen on, and what protection is currently in front of them.

## Configuration sources

The gateway reads configuration in this order. Later sources override earlier ones.

| Order | Source | Tracked by git | Purpose |
| --- | --- | --- | --- |
| 1 | `appsettings.json` | Yes | Safe defaults and placeholder example sites |
| 2 | `appsettings.Local.json` | **No** | Real hostnames and destinations for this machine |
| 3 | `WPSHIELD_` environment variables | No | Deployment and container overrides |
| 4 | Command-line arguments | No | One-off diagnostic overrides |

`appsettings.Local.json` is listed in `.gitignore` and is marked `CopyToPublishDirectory=Never`, so
`dotnet publish` cannot bake operator topology into a release artifact.

## Creating a local overlay

Create `src/WPShield.Gateway/appsettings.Local.json`:

```json
{
  "Sites": [
    {
      "Id": "site-one",
      "Hosts": ["real-site-one.tld", "www.real-site-one.tld"],
      "Destination": "http://127.0.0.1:8081",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    },
    {
      "Id": "site-two",
      "Hosts": ["real-site-two.tld", "www.real-site-two.tld"],
      "Destination": "http://127.0.0.1:8082",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    }
  ]
}
```

> [!WARNING]
> **JSON arrays merge element by element, they do not replace.** This applies to the nested `Hosts`
> array as well as to `Sites`. If `appsettings.json` declares two example sites with two hosts each
> and your overlay declares one site with one host, the surplus shipped entries stay active and
> routable — including `www.wordpress-one.example` inside a site you believed you had fully
> overridden. Declare **every site and every host** explicitly in the overlay.

### The gateway refuses to start on a partial overlay

Because that mistake is silent and dangerous, the startup validator fails closed when real hostnames
appear alongside the RFC 2606 documentation placeholders that ship in `appsettings.json`:

```text
Unhandled exception. System.InvalidOperationException: Configuration mixes real hostnames with the
documentation placeholders shipped in appsettings.json: site-one:www.wordpress-one.example. JSON
configuration merges arrays element by element, so a local overlay that declares fewer sites, or
fewer hosts inside a site, leaves the surplus example entries active and routable. Declare every
site and every host explicitly in appsettings.Local.json.
```

The message names the exact leftover entries. A configuration made entirely of placeholders is the
untouched demonstration configuration and starts normally, so a fresh clone still runs.

### Confirm the resolved site table

The gateway also prints what it actually resolved on every start:

```text
info: WPShield.Gateway.Configuration
      Gateway configuration resolved 2 site(s).
info: WPShield.Gateway.Configuration
      Configured site. SiteId=site-one Hosts=real-site-one.tld, www.real-site-one.tld Destination=http://127.0.0.1:8081/ Mode=Monitor
```

Read that block on every start. If a `*.example` hostname appears, your overlay is incomplete.

## Environment variable form

Use `__` as the section separator:

```powershell
$env:WPSHIELD_Sites__0__Id = "site-one"
$env:WPSHIELD_Sites__0__Hosts__0 = "real-site-one.tld"
$env:WPSHIELD_Sites__0__Destination = "http://127.0.0.1:8081"
$env:WPSHIELD_Sites__0__Mode = "Monitor"
```

The same index-merge caveat applies.

## Trusted proxies

`Gateway:TrustedProxies` lists the peer addresses whose `X-Forwarded-For` and `X-Forwarded-Proto`
headers WPShield will believe. It is **empty by default**, and an empty list means every inbound
forwarding header is stripped and every request is attributed to whatever address connected.

```json
{
  "Gateway": {
    "TrustedProxies": ["127.0.0.1", "::1"]
  }
}
```

### When you need it

Only when something else terminates the client connection. In the loopback laboratory the gateway is
the only hop and the empty default is correct. Under the traffic path chosen in
[ADR 0001](adr/0001-production-traffic-path.md) — IIS keeps ports 80 and 443 and rewrites to the
gateway over loopback — every request arrives from a local proxy, and leaving this empty has two
consequences, one of which is not subtle:

- **Every visitor is recorded as `127.0.0.1`.** Evidence names the proxy instead of the attacker.
- **WordPress decides it was reached over HTTP.** IIS terminates TLS and speaks plain HTTP to the
  gateway, so without an honored `X-Forwarded-Proto` WordPress generates `http://` canonical URLs,
  redirects and login targets behind an HTTPS site. That is a redirect loop, not a degradation.

### What trust does and does not grant

Trust is granted to a **peer address**, never to a header, and it unlocks exactly two headers.

| Header | Untrusted peer | Trusted peer |
| --- | --- | --- |
| `X-Forwarded-For` | Stripped, replaced with the peer address | Honored, replaced with the resolved client |
| `X-Forwarded-Proto` | Stripped, replaced with the connection scheme | Honored if it is exactly `http` or `https` |
| `X-Forwarded-Host` | Replaced with the resolved site host | Replaced with the resolved site host |
| `Forwarded`, every other `X-Forwarded-*` | Stripped | **Stripped** |
| `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, the rest of the client-address family | Stripped | **Stripped** |
| `X-Original-URL`, `X-Rewrite-URL` | Stripped | **Stripped** |
| `X-WPShield-Request-ID` | Stripped | **Stripped** |

The last four rows are the point. A path-override header does not become legitimate because a proxy
presented it, and `X-WPShield-Request-ID` must stay unforgeable from every peer — the loop-prevention
condition in the IIS rewrite rule depends on a client being unable to set it.

### Exact addresses only

A CIDR range is **refused, not unimplemented**:

```text
Unhandled exception. System.InvalidOperationException: Gateway:TrustedProxies:0 ('127.0.0.0/8') is a
CIDR range. Gateway:TrustedProxies accepts exact IP addresses only.
```

These entries decide whose headers become authoritative. A range written one bit too wide grants that
authority to hosts you never intended, and under this traffic path the only trusted peer is a local
proxy, so a range buys nothing. Hostnames are refused for a different reason: the match is against
the peer address of a live connection, which is a number, and no name lookup happens on the request
path.

### The rightmost entry wins

WPShield reads the **rightmost** entry of the `X-Forwarded-For` chain and does not skip entries that
happen to be trusted proxy addresses.

A proxy appends the address it actually saw, so the rightmost entry is the only one the trusted hop
wrote — everything to its left is whatever the client chose to send. The conventional alternative,
walking right to left while skipping trusted entries, is the classic spoof: a client sends
`X-Forwarded-For: 8.8.8.8, 127.0.0.1`, the skip logic steps over the trusted-looking entry, and the
attacker has pinned their own address. WPShield resolves that request to `127.0.0.1`.

This assumes exactly one proxy hop, which is what ADR 0001 specifies. If a header is missing,
malformed or over-long, WPShield falls back to the peer address rather than guessing — wrong in a
visible way, because an operator watching every request arrive from the proxy investigates, while an
operator watching a plausible but attacker-chosen address does not.

> [!IMPORTANT]
> Make the rewrite rule **set** the header rather than hope the proxy appends it. An explicit
> `<set name="HTTP_X_FORWARDED_FOR" value="{REMOTE_ADDR}" />` replaces whatever the client sent, so
> the header carries exactly one entry and it is the one IIS measured. This is validated in the M1.3
> laboratory before any production use.

### Confirm it at startup

The gateway reports which posture it is in, next to the resolved site table:

```text
info: WPShield.Gateway.Configuration
      Trusted proxies configured. X-Forwarded-For and X-Forwarded-Proto are honored from these peers only. TrustedProxies=127.0.0.1, ::1
```

```text
info: WPShield.Gateway.Configuration
      No trusted proxies configured. Every inbound forwarding header is stripped and each request is attributed to the address that connected.
```

Both states are printed because both are wrong somewhere, and behavior alone will not tell you which
one you are in until traffic is already flowing. A non-loopback entry is reported at Warning: the
gateway accepts loopback connections only, so such an entry can never match.

## Inspection bounds

`Gateway:Multipart` holds the bounds for the upload inspection pass. Unlike `Sites`, it is a JSON
**object**, so the element-by-element array merge above does not apply to it: an overlay that sets
one value leaves the rest at their shipped defaults, which is what an operator editing one line
expects.

```json
{
  "Gateway": {
    "Multipart": {
      "ReadTimeoutSeconds": 120
    }
  }
}
```

Every setting, its default and its hard ceiling are documented in
[bounded multipart inspection](m2-multipart-inspection.md). Two things are worth knowing
before you touch them:

- **An out-of-range value prevents startup**, it is not silently clamped. An operator who asks for
  `"MaximumFileCount": 100000` and quietly gets 100 has been told nothing, and configuration must
  never appear to do something it does not.
- **`Gateway:Multipart:Enabled: false` turns the gateway back into a reverse proxy with a size
  limit.** No body is buffered, no sample is taken, and no upload rule runs on live traffic. It is
  an incident escape hatch, not a tuning knob, and the gateway logs a warning on every start while
  it is off.

The gateway prints the bounds it will actually enforce alongside the resolved site table:

```text
info: WPShield.Gateway.Configuration
      Multipart upload inspection enabled. MaximumRequestBytes=6291456 MaximumFileCount=20 MaximumFieldCount=200 MaximumPartHeaderBytes=16384 SampleBytes=4096 ReadTimeoutSeconds=30
```

## Configuration is not hot-reloaded

Gateway and site options are validated once at startup and captured for the lifetime of the process.
Editing `appsettings.json` on a running gateway has **no effect** and produces no warning. Restart
the gateway to apply a change, and read the resolved site table to confirm it took effect.

This is deliberate. A partially applied security configuration is more dangerous than one that
requires a restart.

## What must never be committed

- Real hostnames and their backend destinations.
- Internal IIS port assignments.
- Exact operating system or IIS build numbers.
- The plugin inventory of a specific installation.
- Production logs, even redacted ones, without review.

Keep operator-specific planning notes in `DEVELOPMENT_PLAN.local.md`, which is also ignored by git.

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
> **`Destination` is the private loopback binding, never the public port.** Under
> [ADR 0001](adr/0001-production-traffic-path.md), IIS keeps 80 and 443 and WPShield forwards to a
> *second* binding on the same site that you add for this purpose — `127.0.0.1:8081`. Writing
> `http://127.0.0.1:443` there is the intuitive mistake, because 443 is the port an operator
> associates with the site, and it sends cleartext HTTP at a listener expecting TLS.
>
> That value passes every other rule: it is loopback, and it is not a listener port. The gateway now
> **refuses to start** on a destination port of 80 or 443, because otherwise it starts, reports
> itself healthy, and fails only when a real request arrives — which under this traffic path means
> failing on the live site.
>
> Plain `http://` is correct for that hop. It never leaves the machine; TLS terminates at the public
> IIS binding.

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

## Log files

In Monitor mode the log is the only thing WPShield produces. It forwards every request either way, so
a gateway with nowhere to write is observing traffic and telling nobody — and under a Windows service
there is no console to fall back on.

```json
{
  "Logging": {
    "File": {
      "Enabled": true,
      "Directory": "logs",
      "FileNamePrefix": "wpshield",
      "MaximumFileBytes": 33554432,
      "RetainedFileCount": 14,
      "MaximumQueuedEntries": 10000
    }
  }
}
```

One JSON object per line, UTF-8, no indentation:

```json
{"timestamp":"2026-09-06T04:12:31.4180000+00:00","level":"Information","category":"WPShield.Gateway.Request","message":"Request forwarding. RequestId=8f3a… SiteId=site-one Client=203.0.113.5 Method=GET Path=/wp-admin/","state":{"RequestId":"8f3a…","SiteId":"site-one","Client":"203.0.113.5","Method":"GET","Path":"/wp-admin/"}}
```

The rendered message and the structured fields are both present, so the file is readable by a person
tailing it during a rollout and parseable by whatever aggregates it later. The message template
itself is not written: it would double the size of every line and the rendered message already says
the same thing.

`Directory` is relative to the **content root**, which for a Windows service is the installation
directory rather than `C:\Windows\System32`. An absolute path is used as given. Level filtering uses
the standard provider mechanism, so `Logging:File:LogLevel:Default` works exactly as it does for the
console.

### Rotation and retention

A file is closed and a new one started when it reaches `MaximumFileBytes` or when the UTC date
changes. Names are `wpshield-20260906.jsonl`, then `wpshield-20260906_0001.jsonl` for the second file
of the same day.

> [!NOTE]
> The ordinal separator is `_` rather than `-` on purpose. Retention orders files by name, and `-`
> sorts *before* `.`, so `wpshield-20260906-1.jsonl` would compare as older than the
> `wpshield-20260906.jsonl` it actually succeeds — and retention would have deleted the newest files
> of a busy day while keeping the oldest.

`RetainedFileCount` files are kept and the rest are deleted when a new file opens. A file that cannot
be deleted, because a log viewer holds it open, is skipped rather than retried: retention is
housekeeping and must never become the reason logging stops.

### What a full queue does

Entries are rendered on the calling thread and handed to a bounded queue that a single writer drains.
When that queue is full an entry is **dropped**, not made to wait:

```json
{"timestamp":"…","level":"Warning","category":"WPShield.Gateway.Logging","message":"Log entries were dropped because the write queue was full. The gap is in this file, not in what the gateway did.","state":{"DroppedEntries":42}}
```

Blocking the request path on disk I/O would let a slow or full disk become an outage, and an
unbounded queue would let it become an out-of-memory failure. Dropping is the only one of the three
that the log can afterwards admit to — and it does, as soon as the pressure clears.

### File permissions are not set by the gateway

WPShield creates the directory but does not restrict it. Logs carry real hostnames, real paths and
real client addresses, so the directory ACL is part of installation, not of configuration. Until the
installation procedure lands, restrict it yourself:

```powershell
icacls "C:\ProgramData\WPShield\logs" /inheritance:r `
  /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "<service account>:(OI)(CI)M"
```

### Running as a Windows service

The gateway detects the service control manager on its own; no switch is needed. Under a service it
pins its content root to the installation directory, installs the lifetime that answers stop and
shutdown, and adds the Windows Event Log as a second destination — so a gateway that fails to start
says why somewhere an operator will find it.

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

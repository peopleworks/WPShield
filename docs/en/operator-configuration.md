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

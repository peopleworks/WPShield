# Preflight

`scripts/Invoke-WPShieldPreflight.ps1` checks whether a Windows and IIS host is ready for WPShield to
sit in front of its live sites, and reports every blocker. **It changes nothing** — no IIS setting,
no binding, no rewrite rule, no service, no ACL, no firewall rule.

Run it before anything is installed. Run it again after fixing what it names.

```powershell
.\scripts\Invoke-WPShieldPreflight.ps1
.\scripts\Invoke-WPShieldPreflight.ps1 -SiteName 'example-one','example-two' -OutputPath .\preflight.jsonl
```

Run it elevated. Without elevation the IIS configuration, the listening ports and the directory
permissions are all partly unreadable, and the answer comes out wrong **in the optimistic
direction** — which is the worst direction for a readiness check. The script reports its own lack of
elevation as a blocker for exactly that reason.

## Why this exists

The traffic path in [ADR 0001](adr/0001-production-traffic-path.md) is: IIS keeps ports 80 and 443,
URL Rewrite and ARR send each request to WPShield on a loopback port, and WPShield forwards it back
to a private loopback binding of the same site.

That path has several ways to fail, and they share an unpleasant property: **they fail on the live
site, at the moment the rewrite rule is enabled, with an error that does not say what is wrong.**

- **ARR's server-level proxy switch is off by default.** With it off, a rewrite rule pointing at
  `http://127.0.0.1:10000` does not proxy — it returns **404 for every request**, and nothing in the
  log explains why.
- **ARR does not preserve the client `Host` header by default.** WPShield resolves the site from that
  header and fails closed with **HTTP 421** when it does not match a configured site. With this off,
  the entire site answers 421 the moment the rule goes live.
- **The rewrite rule sends everything to WPShield, and WPShield sends it back to IIS.** If the
  request coming back matches the rule again, it loops.
- **Something else may already own the port.** On a server running dozens of applications, this is
  not hypothetical.

Every one of those is a five-minute fix and a very bad twenty minutes if you find it in production.

## What it checks

| ID | What it answers |
| --- | --- |
| `PRE-001` | Is this session elevated? Blocker if not, because everything below would answer optimistically. |
| `PRE-002` | Windows and PowerShell versions. |
| `PRE-003` | Is an ASP.NET Core 10 runtime present, or is the self-contained build needed? |
| `PRE-004` | Is IIS installed, is `W3SVC` running, is its configuration readable? |
| `PRE-005` | Is URL Rewrite installed? Without it there is no way in. |
| `PRE-006` | Is ARR installed? URL Rewrite can rewrite a URL but cannot forward a request to another process. |
| `PRE-007` | **Is the ARR server-level proxy enabled?** The silent-404 trap. |
| `PRE-008` | **Does ARR preserve the client `Host` header?** The whole-site-421 trap. |
| `PRE-009` | Is the gateway's loopback port free? |
| `PRE-010` | Are the candidate private ports free, or already an IIS binding? |
| `PRE-011` | What holds ports 80 and 443? WPShield never binds a public port. |
| `PRE-012` | Site inventory: bindings, physical path, state, whether it looks like WordPress. |
| `PRE-013` | Existing rewrite rules, which the WPShield rule has to be ordered against. |
| `PRE-014` | Does a WPShield service already exist? Then this is an upgrade, not an install. |
| `PRE-015` | The installation directory and its permissions. |
| `PRE-016` | The log directory: **can unprivileged accounts read it?** |
| `PRE-017` | **Which other applications ARR already proxies** — the blast radius of the `PRE-008` fix. |
| `PRE-018` | Catch-all rewrite rules that stop processing, which the WPShield rule must be ordered before. |

`PRE-016` is a blocker rather than a warning. `C:\ProgramData` is the conventional place for a log
directory and its default ACL grants `BUILTIN\Users` read — so a WPShield log holding request paths,
rule hits and client addresses would be readable by every account on a server that runs other
people's applications.

Each status is one of `Pass`, `Warn`, `Blocker` or `Info`, and **every blocker carries a remedy**. A
readiness check that reports a problem without saying what to do about it has moved the problem
rather than solved it.

## `PRE-017` — the fix for `PRE-008` is server-wide

`preserveHostHeader` lives in `applicationHost.config` under `system.webServer/proxy`, which is a
**server-level section with no per-site override**. So the remedy for `PRE-008` changes the `Host`
header that *every* ARR proxy on the machine sends downstream — not only the ones WPShield will use.

On a server hosting one application that is a fair trade. On a server hosting sixty, some of which
are reverse proxies to other processes, it is a change that has to be made deliberately and verified
immediately. `PRE-017` finds those other proxies by looking for rewrite rules whose action is a
`Rewrite` to an absolute `http://` or `https://` URL, and names them — **before** the switch is
flipped rather than after something stops working.

Most reverse-proxied applications want the original `Host` and improve when they get it. Some are
configured around not getting it. Either way it is not a WPShield-only change, and the operator
should know which applications to re-test.

## `PRE-018` — ordering against a catch-all

A rewrite rule with `stopProcessing="true"` and a `.*` match swallows every request before any rule
placed after it is evaluated. **The WordPress permalink rule has exactly this shape**, so on a
WordPress site the WPShield rule must be ordered *first* or it never runs at all — and the failure
mode is silent: everything keeps working, and nothing is ever inspected.

## The absence of findings is not a finding

When IIS cannot be read, the script emits `PRE-012` as a blocker saying so, rather than printing an
empty site list. On a readiness check, *"there are no sites"* and *"nobody could look"* must never
render the same way — the first invites you to continue and the second does not.

## What it prints at the end

Two things you would otherwise type by hand, which is where the typos that cause a 421 come from.

**The `appsettings.Local.json` to use**, filled in from the sites it found — hostnames, private
destination ports, and `Mode: Monitor`, because WPShield should observe a real site before it refuses
anything on one. The file is **printed, never written**: it belongs on that server, it is gitignored,
and a read-only script should stay read-only.

`TrustedProxies` is set to `127.0.0.1`, which is the peer address ARR presents. If a site uses HTTPS
the script says why that matters: without it, `X-Forwarded-Proto` is discarded, WordPress sees plain
HTTP behind an HTTPS site, and starts emitting `http://` URLs. That is a redirect loop, not a subtle
degradation.

**The rewrite rule**, including its loop guard:

```xml
<rule name="WPShield" stopProcessing="true">
  <match url=".*" />
  <conditions>
    <add input="{HTTP_X_WPSHIELD_REQUEST_ID}" pattern="^$" />
  </conditions>
  <action type="Rewrite" url="http://127.0.0.1:10000/{R:0}" />
</rule>
```

The condition is the loop guard, and **both halves of it are load-bearing.** WPShield stamps
`X-WPShield-Request-ID` on everything it forwards, so the request coming back from the gateway does
not match the rule again. And WPShield *strips* any inbound copy of that header, so a visitor cannot
add it themselves and skip inspection entirely. Remove the stripping and the loop guard becomes an
authentication bypass.

## The report

With `-OutputPath`, findings are written as JSON Lines in the **same envelope the gateway log and the
triage tool use** — `timestamp`, `level`, `category`, `message`, `state` — so all three are read by
one parser. `Blocker` maps to `Error`, `Warn` to `Warning`, everything else to `Information`.

Like the triage report, every string is escaped into printable ASCII, so nothing recovered from the
host can carry a control character or an escape sequence into whoever reads it.

## What it does not do

- **It does not install anything, or fix anything.** Deliberately. On a server running other people's
  applications, changing an IIS setting should not be a side effect of asking a question.
- **It does not prove the path works.** It proves the preconditions hold. Confirming that the rule
  cannot loop, that `Host` survives the ARR hop, and that `X-Forwarded-Proto` reaches WordPress
  requires sending traffic — that is `scripts/Test-WPShieldIisLab.ps1` and the M1.3 checklist.
- **It does not judge the site's security.** That is
  [`Invoke-WPShieldTriage.ps1`](triage-tool.md), and on a host you have any doubt about, it is the
  one to run first: putting a gateway in front of a site that is already compromised protects the
  route in, not the shells already inside.

## See also

- [ADR 0001 — production traffic path](adr/0001-production-traffic-path.md)
- [Triage tool](triage-tool.md)
- [Operator configuration](operator-configuration.md)

# Audit

`wpshield audit` reads how an IIS server is put together and reports the configuration that lets one
compromised site take over the rest. **It changes nothing** — no pool, no permission, no handler
mapping, no binding, no service, no firewall rule.

```powershell
wpshield audit
wpshield audit --output audit.jsonl
```

Run it elevated. Without elevation the pool identities, the handler mappings and the folder
permissions are partly unreadable, and the answer comes out **optimistic**. It reports its own lack of
elevation as `AUDIT-001`, a critical finding, and marks the whole run incomplete rather than printing a
clean report.

## Why this exists

A web shell in one site is an incident. Several configurations of a shared IIS host can turn it into a
compromised server, and no scan of the sites themselves reports any of them:

1. **Application pools that run as an administrator.** A command sent to the shell runs as an
   administrator of the server, not as a restricted web identity.
2. **Site folders writable by every account.** Every pool identity is a member of `Users` and
   `IIS_IUSRS` while it runs, so a shell in one site can write into all the others.
3. **PHP mapped on sites that do not need it.** A PHP mapping inherited from the server or configured
   at the site level can let IIS execute PHP files in a site that does not use PHP.
4. **A site that answers any host name, serving the folder that holds all the others** — the default
   `Default Web Site` on `*:80` over `C:\inetpub\wwwroot`, left in place when the real sites were added
   below it. Stopping a compromised site does not take its files off the internet: they stay reachable
   at the server's address through the catch-all site.
5. **A web root that overlaps an FTP folder.** An FTP account may be able to write files in a folder where
   IIS serves them or executes them as the web site's application pool identity.

None of these is a WordPress problem, and none of them is visible from outside. Together they are the
difference between one compromised site and a compromised server.

## What it checks

| ID | Severity | What it means |
| --- | --- | --- |
| `AUDIT-001` | Critical when it could not look | Running elevated, and the IIS configuration readable. When either fails, the run is marked incomplete and exits `1`: "nobody could look" must never read as "there is nothing there". |
| `AUDIT-002` | Critical | Pools that run as `LocalSystem` or as a direct member of the local Administrators group, identified by SID. The report lists the sites each pool serves. Unresolved accounts warrant a manual check. **Change the password last.** Pools still using the account fail at their next start and their sites return HTTP 503. Each move to `ApplicationPoolIdentity` removes one stored copy of the account's password. |
| `AUDIT-003` | Warning | Pools that share `NetworkService` or `LocalService`. They run as one identity, so no folder permission can keep one of those sites out of another's files. |
| `AUDIT-004` | Warning | Checks the effective handlers at each HTTP/HTTPS site root whether or not the server has a PHP mapping. Names the WordPress sites that should keep PHP, the other sites that run it and sites with unreadable handler configuration. Sites without HTTP/HTTPS bindings appear on a separate line and are excluded from the PHP count. Warns about non-WordPress sites running PHP and unreadable mappings. With neither issue, a server-level PHP mapping is informational and site-level-only PHP passes. |
| `AUDIT-005` | Critical | Site folders that `Everyone`, `Users`, `Authenticated Users` or `IIS_IUSRS` can write into, by SID. Inherit-only entries count, because they grant write on everything below the folder, which is where a dropped file lands. A folder whose permissions cannot be read is a warning, never a pass. |
| `AUDIT-006.<site>` | Critical when started | A site with an HTTP or HTTPS binding that has no host name, whose folder contains other sites' folders. Stopped, it is a warning: nothing is reachable through it today, and everything is the moment it starts. |
| `AUDIT-007` | Warning | The configured root of an HTTP/HTTPS site and an FTP root or virtual directory share a path or one contains the other. This includes a single site bound to both FTP and HTTP/HTTPS. Separate the folders or verify by hand that FTP user isolation keeps every FTP account out of the served folder. The check also warns when it cannot determine the paths it needs. It passes when the folders do not overlap and is informational when IIS has no FTP binding. |

## It never repairs

Every remedy it prints is a change made **by hand**, one pool or one site at a time, with a person
looking at the site while it happens. That is asserted in the tests.

The reason is the same one behind [ADR 0005](adr/0005-putting-wpshield-in-the-path.md) and the
preflight: on a host running other people's applications, moving a pool's identity or replacing a
folder's permissions can take a site down, and a posture tool that "fixed" the server as a side effect
of being asked about it would do exactly that.

## It never reads a password

A pool that runs as a named account keeps that account's password in the IIS configuration, and any
administrator can read it back in plain text. The audit reads the account name and never the
password: the data it carries has no field for one, the reader never touches the attribute, and a
test scans its source for any read of it - by property or by attribute name.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No critical finding. |
| `1` | It could not look — not elevated, IIS unreadable — or an argument was wrong. |
| `2` | At least one critical finding. |

## The report

`--output` writes JSON Lines in the envelope the gateway log, the preflight and the triage tool share —
`timestamp`, `level`, `category`, `message`, `state` — with `category` set to `WPShield.Audit`. Every
item of every list is in it; the terminal output cuts a list after 25 entries and says how many more
there are.

The report carries real site names, folder paths and account names. It is covered by the repository's
`*.jsonl` ignore rule; keep it out of anything public.

## How far it has been tested

The checks are tested on synthetic IIS snapshots. An elevated run on a live IIS host informed the
password, PHP and FTP reporting changes. The FTP check compares configured paths and leaves
verification of actual FTP access and user isolation to the operator.

## What it does not check yet

Stated rather than discovered later:

- **Signatures.** Whether every IIS global module, and binaries such as `sethc.exe` and `utilman.exe`,
  are validly signed by Microsoft. Most Windows binaries are catalog-signed, which .NET has no API to
  verify, so this needs its own careful piece of interop.
- **The host beyond IIS.** WMI event subscriptions, cleared event logs, the size of the Security log,
  firewall rules open to any address, and Microsoft Defender's history. The
  [triage tool](triage-tool.md) covers part of this today.
- **Listening ports and Remote Desktop sign-ins.** Both have their own tools now, outside the audit,
  and the audit reads neither:
  - `wpshield network-monitor --listeners --owners` lists the local TCP listeners and UDP bindings
    with the process ID Windows reported for each, and the desktop monitor shows the same inventory
    ([local listener inventory](network-sensor-design.md#local-listener-inventory),
    [desktop monitor](network-sensor-design.md#desktop-monitor)). Neither compares a port with the
    firewall, so a listening port with a rule open to any address is still not reported anywhere.
  - `wpshield network-monitor --flows --rdp-port <port>` matches each observed incoming Remote
    Desktop flow with its Windows logon outcome and Security record ID
    ([Remote Desktop logon evidence](network-sensor-design.md#remote-desktop-logon-evidence)). It
    reads the last minute of the Security log while it captures, so it shows the sign-ins it sees
    happen; neither tool keeps a history of sign-ins by source address.
- **Behaviour in the IIS logs.** A script that answers POST requests with a different response size
  every time is the signature of a web shell in use, and the most reliable way to find one that no
  signature has caught.
- **Nested group membership.** An account that is an administrator only through a domain group
  nested inside the local Administrators group reads as not a member.
- **Deny entries are coarse.** A deny entry for a broad group removes that group from the writers
  without comparing the two masks. That errs toward reporting less, never toward inventing a writer.

These are the checks the planned console's host posture panel will add, on the same read-only terms.

## See also

- [Preflight](preflight.md) — whether this host is ready for WPShield. The audit asks a different
  question: whether this host is safe to run sites on.
- [Triage tool](triage-tool.md) — what is already on a host that may be compromised.

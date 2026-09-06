# Deployment

How WPShield gets onto a Windows Server host and in front of a live site, and how to take it back
off. Three scripts and four manual IIS steps.

> **WPShield is a research preview and is not approved for production traffic.** Everything below
> assumes a site you can afford to break, in `Monitor` mode, with a rollback you have already
> rehearsed.

## The shape of it

| Step | Who does it | Why |
| --- | --- | --- |
| `Publish-WPShield.ps1` | build machine | Self-contained `win-x64` build, archived with a checksum. |
| `Invoke-WPShieldTriage.ps1` | server | Is this host already compromised? A gateway in front of an existing webshell protects the way in, not what is inside. |
| `Invoke-WPShieldPreflight.ps1` | server | Can the traffic path work here? Clear every blocker. |
| `Install-WPShield.ps1` | server | Directories, ACLs, service, least-privilege identity. |
| **IIS: private binding** | **by hand** | The port WPShield forwards back to. |
| **IIS: `preserveHostHeader`** | **by hand** | Server-wide. See the warning below. |
| **IIS: the rewrite rule** | **by hand** | The switch that puts WPShield in the path. |
| **IIS: verify and watch** | **by hand** | Monitor mode, reading the log, before anything blocks. |
| `Uninstall-WPShield.ps1` | server | Reverses the install. **Not** a rollback on its own. |

The IIS steps are manual on purpose. They are the changes that take a live site down, they need a
person looking at the site while they happen, and on a shared host they affect applications that
have nothing to do with WPShield. `AGENTS.md` makes this an invariant: nothing in this repository
modifies IIS, certificates, DNS, firewall rules or Windows services automatically, and
`Test-WPShieldScripts.ps1` fails the build if an IIS-writing cmdlet appears in any script.

## 1. Build

```powershell
.\scripts\Publish-WPShield.ps1
```

Produces `artifacts\wpshield-<version>-win-x64-RESEARCH-PREVIEW-NOT-FOR-PRODUCTION\`, the same as a
`.zip`, and a `.sha256` beside it. Verify the checksum after copying — a file that arrives damaged is
not a hypothetical.

**Self-contained, deliberately.** A framework-dependent build is smaller and works wherever the
matching runtime is installed. This publishes self-contained anyway, because the host WPShield is
written for is a shared one: a server running dozens of unrelated applications, where somebody
else's patch to the shared runtime should not be able to stop the security gateway.

**Not trimmed.** Trimming would cut the size substantially and would also silently remove types that
configuration binding and dependency injection resolve by reflection. A gateway that fails to start
at 3am because a trimmer removed a binder is worse than a large directory.

The publish refuses to produce an artifact containing `appsettings.Local.json`, and deletes the
output if it finds one. That file carries real hostnames and topology and must never enter a
deployment package.

## 2. Triage first

If there is any doubt about the host, run [the triage tool](triage-tool.md) before anything else.
Putting a gateway in front of a site that is already compromised protects the route in — it does
nothing about the shells already on disk, and it does not remove an intruder who has moved outside
the web root.

## 3. Preflight

```powershell
.\scripts\Invoke-WPShieldPreflight.ps1 -OutputPath .\preflight.jsonl
```

Read-only. Clear every blocker before continuing, and re-run until there are none. See
[preflight](preflight.md) for what each check means. It ends by printing the `appsettings.Local.json`
to use, filled in from the sites it found.

## 4. Install

Preview first. `-WhatIf` prints every step without doing any of it, and does not require elevation:

```powershell
.\scripts\Install-WPShield.ps1 -Path C:\staging\wpshield -WhatIf
```

Then, elevated:

```powershell
.\scripts\Install-WPShield.ps1 -Path C:\staging\wpshield -ConfigurationPath C:\staging\appsettings.Local.json
```

What it does:

- Creates `C:\Program Files\WPShield` and `C:\ProgramData\WPShield\logs`.
- Copies the build, and the operator configuration if you pass one.
- Registers a service named `WPShield`, and only ever that one.
- Gives it the **virtual account `NT SERVICE\WPShield`** — no password to store anywhere, no account
  to manage, and a per-service identity that can be named in an ACL.
- Replaces the permissions on both directories with three entries: SYSTEM and the local
  Administrators group get full control, the service account gets **read and execute** on the
  program files and **modify** on the logs. Inheritance is disabled and the inherited entries are
  discarded rather than copied, because copying them keeps exactly the broad access this removes.
- Configures the service to restart itself after a crash: 5s, 15s, 60s.

Principals are granted by well-known SID, not by name. `BUILTIN\Administrators` is
`BUILTIN\Administradores` on a Spanish Windows, and a script that grants by name silently grants
nothing there.

The service is **not started** unless you pass `-Start`. A gateway with no site configuration
resolves no host, and starting it before the configuration is in place proves nothing.

### Why the log directory permissions matter

`C:\ProgramData` grants `BUILTIN\Users` read by default. A WPShield log carries request paths, rule
hits and client addresses, so on a server running other people's applications that default would
make it readable by every account on the box. `PRE-016` reports that condition; the install must not
be the thing that creates it.

## 5. Confirm it listens, before touching IIS

```powershell
Start-Service WPShield
Invoke-WebRequest http://127.0.0.1:10000/_wpshield/health/ready -UseBasicParsing
```

If that does not answer, stop here. Nothing in IIS has changed yet, so nothing is broken yet.

## 6. The IIS steps, by hand

**a. Add a private loopback binding** to each site, on the destination port from your configuration
— `127.0.0.1:8081`, `127.0.0.1:8082`. This is what WPShield forwards to.

**b. Enable `preserveHostHeader`.**

```powershell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
  -Filter 'system.webServer/proxy' -Name 'preserveHostHeader' -Value $true
```

> **This is server-wide.** `system.webServer/proxy` lives in `applicationHost.config` and has **no
> per-site override**, so this changes the `Host` header that *every* ARR proxy on the machine sends
> downstream — not only the ones WPShield uses. `PRE-017` lists the other proxies by name. Test each
> of them immediately after the change, not the next day. Reverting is the same line with `$false`.

**c. Add the rewrite rule**, to each site:

```xml
<rule name="WPShield" stopProcessing="true">
  <match url=".*" />
  <conditions>
    <add input="{HTTP_X_WPSHIELD_REQUEST_ID}" pattern="^$" />
  </conditions>
  <action type="Rewrite" url="http://127.0.0.1:10000/{R:0}" />
</rule>
```

**Order it first.** A rule with `stopProcessing="true"` and a `.*` match swallows every request
before any later rule is evaluated, and **the WordPress permalink rule has exactly that shape**. Put
the WPShield rule below it and it never runs — and the failure is silent: the site works perfectly
and nothing is ever inspected. `PRE-018` reports which sites have one.

The condition is the loop guard. WPShield stamps `X-WPShield-Request-ID` on everything it forwards,
so the request coming back does not match the rule again; and it **strips any inbound copy**, so a
visitor cannot add the header themselves and skip inspection. Both halves are load-bearing — remove
the stripping and the loop guard becomes an authentication bypass.

## 7. Watch it in Monitor mode

`Monitor` is the default and it should stay that way for as long as it takes to believe the log.
WPShield forwards everything and records what it would have refused. Read
`C:\ProgramData\WPShield\logs`, look for anything that would have been blocked and should not have
been, and only then consider `Block` — one site at a time.

## Rolling back

**This is the part to read before you need it.**

Once the rewrite rule is live, **stopping the service does not bypass WPShield — it takes the site
down.** IIS keeps forwarding every request to a loopback port with nothing behind it, and every
visitor gets an error.

**The bypass is the rewrite rule.** Disable it and traffic goes straight to the site again, whatever
state the service is in. That is the control to reach for, and it is the one to rehearse.

| Situation | Do this |
| --- | --- |
| WPShield is blocking something it should not | Set the site to `Monitor` and restart the service. |
| The gateway is misbehaving and you need the site back now | **Disable the rewrite rule.** |
| Something else broke after `preserveHostHeader` | Set it back to `$false`, then investigate. |
| Removing WPShield for good | Disable the rules, confirm the sites serve, then `Uninstall-WPShield.ps1`. |

## Uninstalling

```powershell
.\scripts\Uninstall-WPShield.ps1 -WhatIf
.\scripts\Uninstall-WPShield.ps1 -RemoveFiles
```

It **refuses to run** while it can still see an enabled WPShield rewrite rule, and equally refuses
when it cannot read the IIS configuration at all — because "nobody could look" is not "there is
nothing there", and on an uninstall that difference decides whether the site stays up. `-Force`
overrides, for when you have confirmed the rule is disabled or the site is already down.

Logs are **kept** by default. They are the record of what the gateway saw, and an uninstall during
an incident is the worst moment to delete evidence. Pass `-RemoveLogs` when you mean it.

The virtual account disappears with the service; there is no account left behind. The IIS bindings
and rules you added by hand are still there — remove those yourself if the gateway is not coming
back.

## What is still open

`ROADMAP.md` M6 tracks the rest: signed releases, and bilingual release notes. The install is
unsigned, which is why it ships with a checksum instead.

## See also

- [Preflight](preflight.md) — clear every blocker before installing.
- [Triage tool](triage-tool.md) — is this host already compromised?
- [ADR 0001 — production traffic path](adr/0001-production-traffic-path.md) — why the path looks like this.
- [Operator configuration](operator-configuration.md)

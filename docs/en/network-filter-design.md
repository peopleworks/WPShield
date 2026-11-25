# Network filter

`wpshield network-filter` previews or enforces host-wide blocks by remote IP address. Keep this
research preview on a disposable Windows Server VM. The gateway remains loopback-only through M2.

## Run the check and preview

Run the check under the Windows identity that will add the filters. The command reports the identity,
the operation Windows denied if applicable, and exit code 0 on success or 1 on failure.

```powershell
wpshield network-filter --check
wpshield network-filter --allow 203.0.113.20 --block 198.51.100.44
```

The check opens a dynamic WFP session and adds, enumerates and deletes one RFC 5737 probe. An elevated
Administrator normally has access. The [VM validation script](network-filter-vm-validation.md)
also shows how to check the actual `NT SERVICE\WPShield` identity through the Service Control Manager.
Monitor is the default and reports operator blocks before exiting. It does not open a WFP session.

## Enforce in the lab

```powershell
wpshield network-filter --mode Block --allow 203.0.113.20 --block 198.51.100.44,2001:db8::44 --output wfp-events.jsonl
netsh wfp show filters file=wfp-filters.xml
```

Use your VM's actual RDP client address in `--allow`. Block checks the configured RDP port and all
established connections to it, rejects overlapping allow/block entries and runs the native self-test
before installing operator filters. Each filter has one IPv4 or IPv6 remote-address condition in the
WPShield ALE receive/accept sublayer. Its scope is the whole host. Dynamic WFP filters are visible
through `netsh wfp show filters`. The Windows Firewall console and `Get-NetFirewallRule` do not list them.

Stop the active enforcer before running another Block process or `--check`. The dynamic sublayer
has one owner per host.

Ctrl+C closes the dynamic session. Process termination and reboot also remove its WFP objects. A hang
can leave current filters active until the process is terminated. For the IIS gateway, disabling its
rewrite rule is the bypass.

## Limits and evidence

- The allow-list supports up to 1,000 entries. Operator blocks may be individual addresses or CIDRs
  of at least /16 for IPv4 and /48 for IPv6. Addresses reserved for local traffic are refused.
- The block set defaults to 1,000 entries and has a ceiling of 10,000. Operator blocks last until the
  session closes. A qualified log finding can add an expiring block or extend its lifetime.
  `--block-ttl-minutes` defaults to 60 with a range of 1–10,080. Expirations are swept every five seconds.
- Native updates run in WFP transactions. If an update fails, the session closes and the error is
  reported. This also prevents stale blocks after a failed expiry.
- Events use the gateway's JSON Lines envelope. A block and its expiry name `WP-NET-001` and
  `requested_by`. Evidence records the normalized address and relevant fixed fields.
- The Security log adapter accepts 4625 records of types 3 and 10. It is a library integration.
  The standalone command enforces operator entries. Connecting the ADR 0009 decision engine
  requires a separate ADR. [Integration design](integration-design.md)

See [ADR 0006](adr/0006-network-layer-blocking.md) for the decision and lab acceptance criteria.

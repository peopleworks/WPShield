# Windows host protection benchmark

WPShield's first comparison with RdpGuard covers Remote Desktop, Microsoft SQL Server and IIS,
the operator's stated priorities. The table defines the full fourteen-service scope.
The baseline is RdpGuard's published documentation checked on 2026-11-22. Relative performance,
coverage and protection effectiveness still need paired measurements. [RdpGuard product overview](https://rdpguard.com/)

RdpGuard documents a Windows service that counts detections, temporarily blocks addresses, and
offers exclusions, IP Cloud and geographic policies. Record enabled options in each run. A local
audit detector and a reputation feed use different evidence. Compare the local detectors under
equivalent conditions and report feed-assisted results separately. [RdpGuard product overview](https://rdpguard.com/)

## Service coverage to evaluate

The last column gives the current WPShield capability where one exists and a proposed acceptance
case for each service. **Planned** means the service-specific integration still needs implementation.
Transport endpoints and byte counts are available across supported TCP/UDP traffic. Identifying
a service, a site or a login outcome requires independent evidence. [Host flow view](network-sensor-design.md#host-flow-view)

| Service | RdpGuard's documented signal | WPShield capability and acceptance case |
| --- | --- | --- |
| Remote Desktop | Windows Security logon failures, supplemented by RdpCoreTS on supported servers. [RDP](https://rdpguard.com/rdp-protection-settings.aspx) | Type 10 logon correlation has synthetic tests. Verify a matching Security record in a Windows Server capture and keep an absent client port unknown. |
| Microsoft SQL Server | SQL login failures such as 18456 in the event log. [SQL Server](https://rdpguard.com/mssql-server-protection.aspx) | The Application log reader reports successful and failed logins per instance. Synthetic tests cover provider isolation. Validate against a known record on a Windows SQL Server and measure missed events. [SQL login evidence](network-sensor-design.md#sql-server-login-evidence) |
| HTTP | Rules match requests and statuses in web access logs. [HTTP](https://rdpguard.com/http-vulnerability-scan-protection.aspx) | The gateway has inline normalized path rules and per-site budgets. Measure these against ordinary requests, including legitimate 404s, on two synthetic sites. |
| IIS Web Login | Windows Security failures for supported IIS authentication schemes. [IIS login](https://rdpguard.com/iis-web-login-protection.aspx) | The offline W3C reader covers a challenge followed by an authenticated request, 401.1 with Win32 1326, and unknown site attribution. Live validation and independent Security audit correlation remain pending. [IIS login evidence](iis-login-evidence.md) |
| FTP | Supported FTP logs, including FTPS, or unencrypted network traffic. [FTP](https://rdpguard.com/ftp-bruteforce-protection.aspx) | **Planned.** Compare a documented server login result over FTP and FTPS. |
| IMAP | Supported mail logs or plaintext IMAP traffic. [IMAP](https://rdpguard.com/imap-bruteforce-protection.aspx) | **Planned.** Verify the mail server's IMAP result over TLS with simultaneous SMTP activity. |
| POP3 | Supported mail logs or plaintext POP3 traffic. [POP3](https://rdpguard.com/pop3-bruteforce-protection.aspx) | **Planned.** Verify a POP3 login result and exclude unrelated mailbox errors. |
| SMTP | SMTP traffic or mail server logs. [SMTP](https://rdpguard.com/stop-smtp-bruteforce.aspx) | **Planned.** Distinguish an authentication rejection from an ordinary delivery rejection. |
| MySQL Server | Login errors from a selected log, including supported Windows and MySQL logs. [MySQL](https://rdpguard.com/mysql-brute-force-protection.aspx) | **Planned.** Identify a denied connection for one instance and exclude SQL statements from output. |
| ASP.NET Forms | Classic ASP.NET request-validation events in the Application log. [Web Forms](https://rdpguard.com/asp-net-web-forms-protection.aspx) | **Planned.** Identify a synthetic validation event without retaining submitted form values or calling it a login failure. |
| RD Web Access | IIS records and Windows Security events for the portal. [RD Web](https://rdpguard.com/rdweb-access-protection.aspx) | **Planned.** Match a portal login with its audit outcome. A 200 response alone leaves the outcome unknown. |
| VoIP / SIP | Authentication traffic over unencrypted IPv4 SIP on TCP or UDP. [SIP](https://rdpguard.com/voip-sip-brute-force-protection.aspx) | **Planned.** Use a supported PBX authentication record and keep a normal challenge-response exchange benign. |
| SSH | Failed authentications in the Windows OpenSSH Operational log. [SSH](https://rdpguard.com/openssh-brute-force-protection.aspx) | **Planned.** Match an OpenSSH refusal, keeping a pre-authentication disconnect separate. |
| Microsoft VPN / RRAS | RemoteAccess event 20271 and IPsec event 4652. [RRAS](https://rdpguard.com/ms-vpn-rras-brute-force-protection.aspx) | **Planned.** Distinguish a VPN authentication refusal from a negotiation failure and identify the available source address. |

WPShield's Security Monitor reports RDP and generic failed-logon findings. The integration
library has an in-memory block-list sink. The CLI leaves findings observational and refuses
`network-filter`. Host-wide prevention trials depend on the replacement tracked in
[draft PR #86](https://github.com/peopleworks/WPShield/pull/86). The flow view independently
reads audit evidence. M3 handles HTTP decisions in the gateway.
Monitor remains the default. M1/M2 listeners remain loopback-only. [Security monitor design](security-monitor-design.md) · [Network filter design](network-filter-design.md) · [ADR 0002](adr/0002-host-level-brute-force-defence.md) · [Roadmap](../../ROADMAP.md)

## Paired evaluation

1. **Fix the comparison before running.** Record both versions, Windows build, hardware, service
   versions, enabled audit fields, time settings, thresholds, exceptions and test interval. Use
   equivalent isolated Windows Server instances and an independent timestamped list of expected
   outcomes. Include source availability and operator setup time.
2. **Exercise each supported input.** Use sanitized synthetic events for offline parsers and
   authorized ordinary logins for live service checks. Include successes, an ordinary mistyped
   password, retries, NAT/shared addresses, port reuse, TLS, missing audits, rotated logs and
   duplicate events. Label each case with its expected service, site or instance, observation,
   detection and action. Record unsupported inputs and skipped trials explicitly.
3. **Publish counts and costs per service.** Report correct detections / eligible positives,
   false alerts / benign trials, unknowns / all trials, and correctly attributed outcomes with
   a traceable source / all attributed outcomes. Measure median and p95 time from the underlying
   event to alert, CPU, peak memory, and dropped events under the same load. Publish denominators,
   repetitions and variation so results can be reproduced.
4. **Verify prevention and recovery independently.** Use a disposable host and an operator-owned
   test identity for a separately authorized prevention trial. Verify the action actually takes
   effect on the intended service, unrelated services and the administrator remain accessible,
   and access returns on expiry or removal. Record false blocks, affected scope and recovery
   time. Give a Monitor-only trial credit for observed detections.
5. **Scope every conclusion.** Name the build, service, configuration and metric for each
   comparison. Publish limitations beside results. Mark missing evidence as unknown and
   untested combinations as pending. Each demonstrated improvement needs a repeatable paired
   result, including its false-alert and false-block counts. For the first three services, agree on
   one primary metric before each run. For example, aim for fewer false blocks at equal detection
   coverage, or lower p95 alert latency at equal detection and false-block rates. An improvement
   that also locks out a legitimate administrator fails the recovery test.

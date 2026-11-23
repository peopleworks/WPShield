# Inspect IIS web login evidence

Use a stable copy of one Windows server's IIS W3C access log. The reader runs offline and requires
only read access to that file. Use the exact site value in its server-generated `s-sitename` column.
Depending on how IIS was configured, this may be an instance number, an instance label or a site name.

```powershell
wpshield iis-login --log-file .\example.log --site W3SVC7 --json
```

Each observation includes the physical line number, UTC timestamp, HTTP status, IIS substatus and
Win32 status. The report includes the SHA-256 and byte length of the input prefix so a reviewer can
find those lines in the same copy. Output omits usernames, addresses, request paths, query strings
and header values. The reader makes no changes to IIS, Windows auditing or the firewall.

| Recorded evidence | Observation |
| --- | --- |
| HTTP 401.1 and Win32 1326 (logon failure) | `login-rejected`. Both values must be present on the same site record. |
| Anonymous 401.2 with Win32 5, or 401.1 with Win32 2148074254 | `challenge-compatible`. The row alone leaves the authentication outcome unknown. |
| HTTP 2xx, zero substatus and Win32 status, and an authenticated `cs-username` | `authenticated-request`. A session can serve multiple requests after login. |
| The preceding challenge-compatible line and this authenticated request meet the criteria below | `challenge-followed-by-success`, with both line references. |
| Other 401 responses | `unknown`. |

Pairing requires adjacent data lines in the same schema for the selected site, HTTP/1.1 on both,
the same two IP addresses and TCP ports, method and URI stem, and UTC timestamps in order within
ten seconds. It describes an observed sequence. Shared proxies, connection reuse or different
queries can still prevent identifying the person or original login. The optional `c-port` column
must be a trusted custom field sourced from the server variable `REMOTE_PORT`. Use existing logs
whose field sources you know. Missing fields, HTTP/2, another intervening line, or a different
endpoint leaves the observations separate.

Rows for other sites are excluded. Rows missing site evidence increment `UnattributedRows`.
Many default per-site logs omit `s-sitename`. Such a file can yield only unknown site attribution
even when its directory name, Host header or listener suggests a site. The parser follows each
`#Fields:` header and expects newline-terminated UTF-8 or ASCII W3C rows.
[IIS log configuration](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile) · [W3C fields](https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging) · [IIS authentication exchanges](https://learn.microsoft.com/en-us/troubleshoot/iis/401-error-preauthentication-header) · [Windows error 1326](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-)

Limits are a 4 MiB prefix, 16 KiB per line, 64 fields, 256 evidence rows and a five-second read
and parse budget. Exit 0 means eligible evidence was read. Exit 1 means invalid arguments or an
unavailable file. Exit 2 means a limit, malformed input or unknown site coverage made the report
partial. Exit 3 means a completed scan found no eligible evidence. Validate on a lab server by
checking both line references against an authorized IIS access. Synthetic fixtures cover this
reader; a live deployment and comparison against Windows Security events remain pending.

## Selected line reference

```powershell
wpshield iis-login --log-file .\example.log --site W3SVC7 --json | Set-Content -Encoding UTF8 .\iis.json
wpshield audit-reference --snapshot .\iis.json --source iis --line 3
```

Choose the physical `Line` of an evidence row in the saved report. The output contains the
SHA-256 and byte length of the input prefix, the selected line, and the preceding challenge line
when the reader paired the two. To verify it, hash that many leading bytes of the original W3C
copy and inspect the indicated lines. A changed prefix identifies different input. The export
copies the reference already present in the snapshot. [Selection limits and exit codes](network-sensor-design.md#selected-audit-reference)

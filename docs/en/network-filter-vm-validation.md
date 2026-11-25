# Validate WFP blocking on a disposable VM

Use a fresh Windows Server VM on a private virtual switch with a hypervisor console, a snapshot, an
allowed management client and a separate test client. Use isolated lab addresses throughout. Keep
M1/M2 gateway listeners on loopback. Run this procedure only in the disposable VM, never on the
production server. Record the commit, Windows build, test addresses, sublayer GUID
`93a54814-5f1d-44f3-b2ba-f4df18dfe12f`, test times and observed results.

1. **Firewall arbitration.** Run `wpshield network-filter --check` in an elevated Administrator
   console. Start a temporary TCP listener in the VM and manually allow its port in Windows Firewall.
   Verify a fresh connection from the test client. Start `wpshield network-filter --mode Block
   --allow 203.0.113.20 --block 198.51.100.44`, substituting the lab client addresses. Repeat the
   connection and confirm refusal. Save `netsh wfp show filters file=wfp-filters.xml` and find the
   WPShield sublayer and filter in it. Repeat using an authenticated firewall allow rule with
   **Override block rules** and a client that matches its authentication requirements. Record
   whether it overrides the WPShield block. Remove the temporary firewall rules after the exercise.
2. **Forced exit.** Start rapid, separately timed fresh connections from the blocked client. From the
   VM console, run `taskkill /F /PID <wpshield-pid>` against the enforcer. Measure the time from process
   death to the first successful connection and require it to be under one second. Run
   `netsh wfp show filters file=wfp-after-kill.xml` and confirm that every WPShield filter disappeared.
3. **RDP.** Use an established RDP session from the allow-listed management client. Start a block
   for the other test client and verify the RDP session remains responsive. Remove the management IP
   from the argument and confirm Block refuses to start when that connection is still active.
4. **10,000 filters.** From an elevated shell, run the [load harness](#load-harness). Its synthetic
   addresses are for this isolated VM only. Record elapsed startup time, private memory of the Base
   Filtering Engine process (`sc.exe queryex BFE` gives its PID) and fresh connection setup latency
   for a client outside the test range before, during and after the run. Record sample count, median
   and p95. Confirm that WFP has 10,000 WPShield filters, stop the harness, and confirm cleanup.
5. **Endpoint protection.** Repeat items 1–3 with the lab's third-party endpoint protection network
   feature enabled. Exercise a benign connection that the product's own lab policy blocks before
   and after adding the WPShield filter. Verify its block remains effective and review the system
   event log for crashes or destabilization. Record the product and version.
6. **Identity.** Record the elevated Administrator check and repeat under the actual WPShield
   virtual service account using the recipe below. Record the failing operation and status code if
   denied. Keep the standalone Administrator enforcer until a separate ADR authorizes any decision
   engine connection or WFP permission change. This recipe grants no WFP rights.

The Windows Firewall console and `Get-NetFirewallRule` show the VM's manually created firewall rules.
Use `netsh wfp show filters` for WPShield's dynamic filters.

## Test the WPShield service identity

Use a disposable VM where a service named `WPShield` is absent. Put a published CLI and its runtime
files in `C:\WfpLab\cli`, with read/execute for the virtual account. In an elevated **Command Prompt**,
create a demand-start diagnostic instance through the Service Control Manager. The service name and
account name must correspond. Give the virtual account write access to the results directory only.

```bat
mkdir C:\WfpLab\results
sc.exe create WPShield binPath= "C:\WfpLab\cli\wpshield.exe network-filter --check --service-check-output C:\WfpLab\results\wfp-check.txt" start= demand obj= "NT SERVICE\WPShield"
icacls C:\WfpLab\cli /grant "NT SERVICE\WPShield:(OI)(CI)RX"
icacls C:\WfpLab\results /grant "NT SERVICE\WPShield:(OI)(CI)M"
sc.exe qc WPShield
sc.exe start WPShield
type C:\WfpLab\results\wfp-check.txt
sc.exe stop WPShield
sc.exe delete WPShield
```

The file should identify `NT SERVICE\WPShield`. The service is a diagnostic entry point and stays
available for `sc.exe stop` after writing the result. A session started with PsExec `-i -s` runs as
`LocalSystem` and cannot establish the virtual account's permissions. Revert the VM snapshot at
the end of the exercise.

## Load harness

Create a temporary `net10.0-windows` console app outside the checkout and reference
`src/WPShield.NetworkFilter/WPShield.NetworkFilter.csproj`. Save the following as its `Program.cs`
and run in Release. Set the allow-list to the management client's lab address.

```csharp
using System;
using System.Diagnostics;
using System.Linq;
using WPShield.NetworkFilter;

IpRange.TryParseAllow("203.0.113.20", out var allowed, out _);
var blocks = Enumerable.Range(0, 10_000)
    .Select(i =>
    {
        IpRange.TryParseBlock($"198.18.{i / 256}.{i % 256}", out var range, out _);
        return range!;
    }).ToArray();
using var service = new NetworkFilterService(new NetworkFilterOptions
{
    Mode = NetworkFilterMode.Block,
    AllowList = [allowed!],
    Blocks = blocks,
    MaximumBlocks = 10_000,
}, new NoOutput());
var stopwatch = Stopwatch.StartNew();
var outcome = service.Start();
Console.WriteLine($"Started={outcome.Started} elapsed_ms={stopwatch.ElapsedMilliseconds} {outcome.Refusal}");
if (outcome.Started)
{
    Console.ReadLine();
}
return outcome.Started ? 0 : 1;

sealed class NoOutput : INetworkFilterEventSink
{
    public void Write(NetworkFilterEvent entry) { }
}
```

using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop.Demo;

internal static class DemoData
{
    internal static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 42, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Hour = Now.AddMinutes(-42);
    private static readonly DateTimeOffset RecentLogonCoverage = Now.AddHours(-23);
    private static readonly string[] Addresses =
    [
        "203.0.113.21", "203.0.113.22", "203.0.113.23", "198.51.100.41", "198.51.100.42",
        "192.0.2.61", "192.0.2.62", "192.0.2.63", "203.0.113.27"
    ];
    private static readonly string[] Sites =
    [
        "blog.example", "shop.example", "forum.example", "media.example", "catalog.example", "learn.example",
        "events.example", "news.example", "gallery.example", "archive.example", "support.example", "studio.example"
    ];
    private static readonly IReadOnlyList<AuthFailure> Failures = FailedLogons();

    internal static void WriteStore(string path)
    {
        // A new file in our private workspace establishes the invariant before SQLite opens it.
        using (new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
        using var store = EvidenceStore.OpenForWriting(path);
        WriteLogons(store);
        WriteWeb(store);
        WriteHost(store);
        WriteSettings(store);
    }

    internal static AuthFailureSnapshot RecentLogons(DateTimeOffset end)
    {
        var from = end.AddHours(-24);
        var failures = Failures.Where(f => f.Timestamp >= RecentLogonCoverage && f.Timestamp < end).ToArray();
        return new(from, end, failures,
        [
            new(AuthFailureFeed.SecurityChannel, "read", null, null, RecentLogonCoverage,
                failures.Count(f => f.Channel == AttemptPairing.SecurityChannel)),
            new(AuthFailureFeed.RdpCoreChannel, "read", null, null, RecentLogonCoverage,
                failures.Count(f => f.Channel == AttemptPairing.RdpChannel))
        ]);
    }

    private static IReadOnlyList<AuthFailure> FailedLogons()
    {
        var addresses = Addresses.Select(IPAddress.Parse).ToArray();
        string[] accounts = ["demo-archive", "demo-studio", "demo-editor", "demo-operator"];
        var failures = new List<AuthFailure>();
        for (var hoursAgo = 167; hoursAgo >= 0; hoursAgo--)
        {
            var hour = Hour.AddHours(-hoursAgo);
            var burst = hoursAgo switch
            {
                0 => 35,
                3 or 4 => 54,
                10 => 42,
                _ when hoursAgo % 11 == 0 => 26,
                _ => 1 + hoursAgo % 6
            };
            for (var i = 0; i < burst; i++)
            {
                var at = hour.AddMinutes((i * 7 + hoursAgo * 3) % 39).AddSeconds(i);
                if (at >= Now || (at >= Now.AddHours(-24) && at < RecentLogonCoverage)) continue;
                var address = addresses[(i * 7 + hoursAgo % 3) % addresses.Length];
                var unknown = (i + hoursAgo) % 4 != 0;
                var smb = i % 3 == 0;
                var channel = smb || i % 4 == 0 ? AttemptPairing.SecurityChannel : AttemptPairing.RdpChannel;
                failures.Add(new(at, channel, address, null, accounts[(i + hoursAgo) % accounts.Length],
                    unknown ? "unknown-account" : "bad-password", smb ? 3 : 10, 1000 + failures.Count));
            }
        }
        return failures;
    }

    private static void WriteLogons(EvidenceStore store)
    {
        var writer = new EvidenceWriter(store);
        writer.Append(Failures);
        writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-7), Now.AddHours(-24));
        writer.BeginCoverage(EvidenceWriter.RawSource, RecentLogonCoverage, Now);
        writer.RecordEngineStart(Now.AddHours(-5));
        writer.RecordDecision(new(Now.AddMinutes(-18), DecisionActions.WouldBlock, Addresses[0], DecisionRules.RepeatedFailures,
            DecisionActions.MonitorMode, "Repeated failed logons in the demo window", AttemptPairing.SecurityChannel, Now.AddMinutes(42)));
        writer.RecordDecision(new(Now.AddMinutes(-12), DecisionActions.WouldBlock, "192.0.2.0/24", DecisionRules.Network,
            DecisionActions.MonitorMode, "Failed logons from neighbours in the demo network", AttemptPairing.RdpChannel, Now.AddMinutes(48)));
        writer.RecordDecision(new(Now.AddMinutes(-8), DecisionActions.Protected, Addresses[^1], DecisionRules.RepeatedFailures,
            DecisionActions.MonitorMode, "Matches the demo allow-list", AttemptPairing.SecurityChannel, null));
        writer.RecordDecision(new(Now.AddMinutes(-24), DecisionActions.Report, Addresses[3], DecisionRules.SharedAccount,
            DecisionActions.MonitorMode, "Repeated attempts on one synthetic account", AttemptPairing.SecurityChannel, null));
    }

    private static void WriteWeb(EvidenceStore store)
    {
        var writer = new WebEvidenceWriter(store);
        var coverage = new EvidenceWriter(store);
        var from = Hour.AddHours(-20);
        coverage.BeginCoverage(WebEvidenceWriter.SensorSource, from, Now);
        var states = new List<WebSiteState>();
        var totals = new List<WebSiteCounts>();
        var sources = new List<WebSourceCounts>();
        var findings = new List<WebFinding>();
        for (var site = 1; site <= Sites.Length; site++)
        {
            var name = Sites[site - 1];
            if (site == Sites.Length)
            {
                coverage.BeginCoverage(WebEvidenceWriter.SiteSource(site), from, Now, "unavailable", "access-denied");
                states.Add(new(site, name, "unavailable", "access-denied", "Grant the collector read access to this site's IIS logs.",
                    false, Now.AddMinutes(-3)));
                continue;
            }
            coverage.BeginCoverage(WebEvidenceWriter.SiteSource(site), from, Now);
            states.Add(new(site, name, "collected", null, null, false, Now.AddMinutes(-3)));
            for (var hoursAgo = 20; hoursAgo >= 0; hoursAgo--)
            {
                var hour = Hour.AddHours(-hoursAgo);
                var requests = 105 + (site * 47 + 19 * hoursAgo) % 280;
                var flagged = (site + hoursAgo) % 9 == 0 || hoursAgo <= 2;
                var observed = site == 1 && hoursAgo == 0;
                var login = flagged ? 3 + (site + hoursAgo) % 11 : 0;
                var xmlrpc = flagged ? (site + 2 * hoursAgo) % 5 : 0;
                totals.Add(new(site, hour, requests, 2 + login, 0, flagged ? 1 : 0, observed ? 1 : 0, login, xmlrpc, requests * 510L));
                if (!flagged) continue;

                var address = Addresses[(site - 1 + 2 * hoursAgo) % Addresses.Length];
                var at = hour.AddMinutes(5 + (site * 7 + hoursAgo) % 34);
                sources.Add(new(site, hour, address, 8 + login + xmlrpc, 2 + login, 1, observed ? 1 : 0, login, xmlrpc,
                    hour.AddMinutes(2), at, null));
                IReadOnlyList<WebHit> hits = observed
                    ? [new("WP-PATH-001", 100), new(WebObservationIds.PhpOutsideEntryPoints, 0)]
                    : [new("WP-PATH-001", 100)];
                findings.Add(new(at, site, address, "GET", "/wp-content/uploads/demo-marker.php", observed ? 200 : 404,
                    hits, "", true, false, null));
            }
        }
        writer.RecordSites(states, Now);
        writer.Write(new(findings, totals, sources, []));
    }

    private static void WriteHost(EvidenceStore store)
    {
        var writer = new HostFactsWriter(store);
        var patch = new HostPatchLevel("20348", 4321, "21H2", "10.0.20348.4321", true,
            "Cumulative Update (demo)", Now.AddDays(-9), 0);
        HostHealth HealthSample(int hoursAgo) => new(Now.AddDays(-3), (long)TimeSpan.FromDays(3).TotalSeconds,
            24 + hoursAgo % 6 * 6 + (hoursAgo is 7 or 8 ? 22 : 0),
            GiB(32), GiB(13) + GiB(1) * (hoursAgo % 4), [new("D:", GiB(400), GiB(190 + hoursAgo), true)], 1_800_000, patch);

        for (var hoursAgo = 23; hoursAgo >= 0; hoursAgo--) writer.RecordHealth(HealthSample(hoursAgo), Hour.AddHours(-hoursAgo));
        writer.Write(HostFactReading.Of(HostFacts.Health, null, Now.AddMinutes(-2), HealthSample(0)));
        writer.RecordRestarts(Enumerable.Range(0, 5).Select(i => new HostRestart($"demo-restart-{i}",
            Now.AddDays(-3 - 5 * i), [41, 1001], 0x133)).ToArray());
        writer.SetRestartsReadUntil(Now.AddMinutes(-2));

        for (var i = 0; i < 4; i++)
        {
            var taken = i == 3 ? Now.AddHours(-1) : Now.AddDays(-21 + i * 7);
            writer.Write(HostFactReading.Of(HostFacts.Posture, null, taken, new HostPosture("collector", true,
                [new("AUDIT-002", "critical", "Demo pools running as administrator", 9 - i)], 10, 9 - i, i < 2, 4 - i, 1)));
        }
        writer.Write(HostFactReading.Of(HostFacts.Ports, null, Now.AddMinutes(-4), new HostPorts(
        [
            new("TCP", 445, "any", null, "System", null, ExposureVerdicts.OpenToAny, true),
            new("TCP", 1433, "specific", Addresses[7], "demo-db.exe", null, ExposureVerdicts.Restricted, false),
            new("TCP", 443, "any", null, "demo-web.exe", null, ExposureVerdicts.OpenToAny, false),
            new("TCP", 5985, "specific", Addresses[7], "demo-admin.exe", null, ExposureVerdicts.Restricted, false)
        ], true)));
        writer.Write(HostFactReading.Of(HostFacts.Sites, null, Now.AddMinutes(-4), new HostSites(
            Sites.Select((name, i) => new HostSite(i + 1, name, "Started", [new("https", 443, name, false)],
                $"demo-pool-{i % 10 + 1}", i % 10 < 6 ? "SpecificUser" : "ApplicationPoolIdentity", i % 10 < 6)).ToArray())));
        writer.Write(HostFactReading.Of(HostFacts.Sessions, null, Now.AddMinutes(-4), new HostSessions(
            [new(7, "Active", "demo-operator", Now.AddHours(-2))], [new(Now.AddHours(-2), "demo-operator", Addresses[^1], "logon")])));
        writer.Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Accounts, Now.AddHours(-1),
            new HostAccounts([new("demo-operator", true, false, true, Now.AddHours(-2), 32, false)], true, 1)));
        writer.Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Services, Now.AddHours(-1),
            new HostServices([new("DemoArchive", "Demo archive service", "Running", "Auto", "demo-archive",
                @"D:\Demo\archive.exe", HostSignature.Unsigned, null, [])], 0)));
        writer.Write(HostFactReading.Of(HostFacts.Inventory, HostFacts.Tasks, Now.AddHours(-1),
            new HostTasks([new(@"\Demo\Archive", "Ready", "demo-archive", Now.AddHours(-4), Now.AddHours(20),
                @"D:\Demo\archive.exe", HostSignature.Unsigned, null, [])], 0)));
        writer.RecordInventoryChanges(HostFacts.Tasks, [new(HostFacts.Tasks, "added", @"\Demo\Archive", [])], Now.AddDays(-2));
    }

    private static long GiB(long value) => value * 1024 * 1024 * 1024;

    private static void WriteSettings(EvidenceStore store)
    {
        var settings = new EvidenceSettings(store);
        settings.Set(DefenseSettings.Allow, """["203.0.113.27"]""", "demo-operator", "Allow the demo publishing partner", Now.AddHours(-2));
        settings.Set(AddressLabels.SettingKey, """{"203.0.113.27":"Demo publishing partner","192.0.2.0/24":"Demo edge network","198.51.100.0/24":"Demo lab network"}""",
            "demo-operator", "Name the example networks", Now.AddHours(-3));
    }

    internal static void WriteAudit(string path)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var stamp = Now.AddMinutes(-18);
        var prefix = "# Synthetic W3C demo\r\n"u8;
        var rdpEvents = new[]
        {
            new { RecordId = 1042, Timestamp = stamp },
            new { RecordId = 1043, Timestamp = stamp.AddMinutes(1) }
        };
        JsonSerializer.Serialize(file, new
        {
            RdpAudit = new { AuditStatus = "read", Flows = new[] { new { Events = rdpEvents } } },
            SqlAudit = new
            {
                Channel = "Application",
                Provider = "MSSQL$DEMO",
                AuditStatus = "limited",
                Events = new[] { new { RecordId = 187, Timestamp = stamp.AddMinutes(3) } }
            },
            InputPrefixSha256 = Convert.ToHexString(SHA256.HashData(prefix)).ToLowerInvariant(),
            InputPrefixBytes = prefix.Length,
            Report = new
            {
                StopReason = "end_of_file",
                MalformedRows = 0,
                UnattributedRows = 0,
                Evidence = new[] { new { Line = 5, ChallengeLine = 4 }, new { Line = 7, ChallengeLine = 6 } }
            }
        });
    }
}

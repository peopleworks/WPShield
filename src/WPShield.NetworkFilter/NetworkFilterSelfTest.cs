using System.Net;

namespace WPShield.NetworkFilter;

/// <summary>
/// Asks the real WinDivert library whether the filters WPShield writes mean what WPShield thinks they
/// mean, before any of them is trusted with traffic (ADR 0006, section 8).
/// </summary>
/// <remarks>
/// <para>
/// Uses only <c>WinDivertHelperCompileFilter</c> and <c>WinDivertHelperEvalFilter</c>, which are
/// user-mode functions: no driver, no elevation, no handle. Two plans are tested. A fixed probe plan
/// pins down the semantics on every run whatever is configured - single addresses, an IPv4 /24 and an
/// IPv6 /64 with their edges and the addresses just outside them, and allow-listed neighbours. Then the
/// configured plan, sampled, so the operator's own entries are proven too.
/// </para>
/// <para>
/// The WinDivert documentation does not state how <c>&gt;=</c> and <c>&lt;=</c> order addresses. This
/// test is why ranges can ship anyway: if the library disagrees, Block mode does not start.
/// </para>
/// </remarks>
public static class NetworkFilterSelfTest
{
    public const int SampleLimit = 64;

    private static readonly IPAddress Ipv4Destination = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress Ipv6Destination = IPAddress.Parse("2001:db8::1");

    public static SelfTestReport Run(IDivertDriver driver, IReadOnlyList<IpRange> allowList, IReadOnlyList<IpRange> blocks)
    {
        ArgumentNullException.ThrowIfNull(driver);
        ArgumentNullException.ThrowIfNull(allowList);
        ArgumentNullException.ThrowIfNull(blocks);

        var checks = new List<SelfTestCheck>();
        CheckObserver(driver, checks);
        CheckProbePlan(driver, checks);
        CheckConfiguredPlan(driver, allowList, blocks, checks);
        return new SelfTestReport(checks);
    }

    private static void CheckObserver(IDivertDriver driver, List<SelfTestCheck> checks)
    {
        var compiled = driver.Compile(DivertFilterBuilder.ObserverFilter);
        checks.Add(new SelfTestCheck("observer filter compiles", compiled.Succeeded, compiled.Error));
        if (!compiled.Succeeded)
        {
            return;
        }

        var source = IPAddress.Parse("198.51.100.7");
        checks.Add(Expect(driver, [DivertFilterBuilder.ObserverFilter], source, syn: true, ack: false, expected: true, "observer sees a new connection attempt"));
        checks.Add(Expect(driver, [DivertFilterBuilder.ObserverFilter], source, syn: true, ack: true, expected: false, "observer ignores a SYN-ACK"));
        checks.Add(Expect(driver, [DivertFilterBuilder.ObserverFilter], source, syn: false, ack: true, expected: false, "observer ignores established traffic"));
    }

    private static void CheckProbePlan(IDivertDriver driver, List<SelfTestCheck> checks)
    {
        IpRange[] blocks =
        [
            Parse("192.0.2.10"), Parse("198.51.100.0/24"), Parse("2001:db8::10"), Parse("2001:db8:1::/64"),
        ];
        IpRange[] allow = [Allow("192.0.2.20"), Allow("2001:db8::20")];
        var plan = DivertFilterBuilder.BuildDropFilters(blocks, allow);
        if (!CompileAll(driver, plan, "probe", checks))
        {
            return;
        }

        (string Address, bool Dropped)[] cases =
        [
            ("192.0.2.10", true), ("192.0.2.11", false), ("192.0.2.20", false),
            ("198.51.100.0", true), ("198.51.100.255", true), ("198.51.99.255", false), ("198.51.101.0", false),
            ("2001:db8::10", true), ("2001:db8::11", false), ("2001:db8::20", false),
            ("2001:db8:1::", true), ("2001:db8:1:0:ffff:ffff:ffff:ffff", true),
            ("2001:db8:0:ffff:ffff:ffff:ffff:ffff", false), ("2001:db8:1:1::", false),
        ];

        foreach (var (address, dropped) in cases)
        {
            checks.Add(Expect(driver, plan.Filters, IPAddress.Parse(address), syn: true, ack: false, dropped, $"probe: {address} {(dropped ? "dropped" : "passes")}"));
        }
    }

    private static void CheckConfiguredPlan(
        IDivertDriver driver,
        IReadOnlyList<IpRange> allowList,
        IReadOnlyList<IpRange> blocks,
        List<SelfTestCheck> checks)
    {
        var plan = DivertFilterBuilder.BuildDropFilters(blocks, allowList);
        checks.Add(new SelfTestCheck(
            "no configured block overlaps the allow-list",
            plan.Excluded.Count == 0,
            plan.Excluded.Count == 0 ? null : "overlapping: " + string.Join(", ", plan.Excluded)));

        if (plan.Filters.Count == 0 || !CompileAll(driver, plan, "configured", checks))
        {
            return;
        }

        foreach (var range in blocks.Except(plan.Excluded).Take(SampleLimit))
        {
            checks.Add(Expect(driver, plan.Filters, range.First, syn: true, ack: false, expected: true, $"configured: {range} first address dropped"));
            if (!range.IsSingleAddress)
            {
                checks.Add(Expect(driver, plan.Filters, range.Last, syn: true, ack: false, expected: true, $"configured: {range} last address dropped"));
            }
        }

        foreach (var range in allowList.Take(SampleLimit))
        {
            checks.Add(Expect(driver, plan.Filters, range.First, syn: true, ack: false, expected: false, $"allow-list: {range} first address passes"));
            if (!range.IsSingleAddress)
            {
                checks.Add(Expect(driver, plan.Filters, range.Last, syn: true, ack: false, expected: false, $"allow-list: {range} last address passes"));
            }
        }
    }

    private static bool CompileAll(IDivertDriver driver, DropFilterPlan plan, string label, List<SelfTestCheck> checks)
    {
        var ok = true;
        for (var index = 0; index < plan.Filters.Count; index++)
        {
            var compiled = driver.Compile(plan.Filters[index]);
            checks.Add(new SelfTestCheck(
                $"{label}: drop filter {index + 1} of {plan.Filters.Count} compiles",
                compiled.Succeeded,
                compiled.Succeeded ? null : $"{compiled.Error} at position {compiled.ErrorPosition}"));
            ok &= compiled.Succeeded;
        }

        return ok;
    }

    private static SelfTestCheck Expect(
        IDivertDriver driver,
        IReadOnlyList<string> filters,
        IPAddress source,
        bool syn,
        bool ack,
        bool expected,
        string name)
    {
        var ipv6 = source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var packet = SyntheticPacket.Tcp(source, ipv6 ? Ipv6Destination : Ipv4Destination, 443, syn, ack);
        var matched = filters.Any(filter => driver.Evaluate(filter, packet, ipv6));
        return new SelfTestCheck(name, matched == expected, matched == expected ? null : $"expected {(expected ? "a match" : "no match")}, got {(matched ? "a match" : "no match")}");
    }

    private static IpRange Parse(string text) =>
        IpRange.TryParseBlock(text, out var range, out var error) ? range! : throw new InvalidOperationException(error);

    private static IpRange Allow(string text) =>
        IpRange.TryParseAllow(text, out var range, out var error) ? range! : throw new InvalidOperationException(error);
}

public sealed record SelfTestCheck(string Name, bool Passed, string? Detail);

public sealed record SelfTestReport(IReadOnlyList<SelfTestCheck> Checks)
{
    public bool Passed => Checks.Count > 0 && Checks.All(check => check.Passed);

    public IEnumerable<SelfTestCheck> Failures => Checks.Where(check => !check.Passed);
}

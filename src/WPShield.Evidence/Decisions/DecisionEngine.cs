using System.Globalization;
using System.Net;

namespace WPShield.Evidence.Decisions;

/// <summary>The engine's bounds (ADR 0009, section 5). Tests shrink them; the service uses the defaults.</summary>
public sealed record DecisionEngineLimits
{
    /// <summary>Entries per map: addresses, networks, accounts, repeat memory, protected and refused targets.</summary>
    public int MaxEntries { get; init; } = 100_000;

    /// <summary>
    /// Items inside one map's entries (timestamps, names, member addresses). Without it, 100,000 entries
    /// each holding a full window would be a far larger amount of memory than the entry bound suggests.
    /// </summary>
    public long MaxItems { get; init; } = 1_000_000;

    /// <summary>Would-block decisions in force at once. Past it a new one is refused, and the refusal recorded.</summary>
    public int MaxActive { get; init; } = 10_000;
}

/// <summary>
/// Turns live failed logons into decisions with a rule, a reason and an expiry (ADR 0009). This version
/// runs in Monitor only: every decision is a record, and nothing anywhere is enforced.
/// </summary>
/// <remarks>
/// <para>
/// <b>Live evidence only.</b> It is fed paired records that arrived after the process started, never the
/// catch-up read at start, and it never reads the <c>decisions</c> table. Everything it knows - counters,
/// decisions in force, the memory of repeat offenders - is in this object and ends with the process, so a
/// decision can never outlive the process that made it (ADR 0006, section 2; ADR 0007, section 5).
/// </para>
/// <para>
/// <b>Pure.</b> No clock, no store, no Windows: time is passed in, settings arrive as a snapshot, and the
/// facts about the host come through <see cref="AddressProtection"/>. Not thread-safe; the collector's
/// own loop is its only caller.
/// </para>
/// <para>
/// <b>One record per target while it lasts.</b> Monitor does not stop the failures, so a rule that fired
/// would fire again on every next attempt. While a would-block decision is in force the engine ignores the
/// target's failures, exactly as an enforced block would have dropped them; a protected or refused target
/// is not reconsidered until its quiet period ends.
/// </para>
/// <para>
/// <b>No account name leaves it.</b> Reasons carry counts and the target carries an address. The MCP
/// server returns both regardless of <c>mcp.detailed_records</c>, so a name written here would leave the
/// host through a door that is otherwise closed to it.
/// </para>
/// </remarks>
public sealed class DecisionEngine
{
    /// <summary>A repeat within this long of the end of a previous decision doubles the duration.</summary>
    public static readonly TimeSpan RepeatWithin = TimeSpan.FromDays(7);

    /// <summary>The longest any decision lasts, escalated or not.</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromDays(7);

    /// <summary>State older than the longest window a setting accepts is useless and dropped.</summary>
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(DefenseSettings.MaxWindowMinutes);

    /// <summary>Reasons Windows gives only for an account that exists (AuthFailureFeed's codes).</summary>
    private static readonly HashSet<string> ExistingAccountReasons = new(StringComparer.Ordinal)
    {
        "bad-password", "locked-out", "disabled", "account-expired", "password-expired", "password-must-change",
        "outside-hours", "workstation-restricted", "logon-type-denied"
    };

    private readonly AddressProtection protection;
    private readonly DecisionEngineLimits limits;
    private readonly BoundedMap<string, AddressState> addresses;
    private readonly BoundedMap<string, MemberSet> networks;
    private readonly BoundedMap<string, MemberSet> accounts;
    private readonly BoundedMap<string, Previous> history;
    private readonly BoundedMap<string, Hold> quiet;
    private readonly Dictionary<string, Hold> active = new(StringComparer.Ordinal);

    public DecisionEngine(AddressProtection protection, DecisionEngineLimits? limits = null)
    {
        this.protection = protection ?? throw new ArgumentNullException(nameof(protection));
        this.limits = limits ?? new DecisionEngineLimits();
        addresses = new(this.limits.MaxEntries, this.limits.MaxItems, StringComparer.Ordinal);
        networks = new(this.limits.MaxEntries, this.limits.MaxItems, StringComparer.Ordinal);
        accounts = new(this.limits.MaxEntries, this.limits.MaxItems, StringComparer.OrdinalIgnoreCase);
        history = new(this.limits.MaxEntries, this.limits.MaxEntries, StringComparer.Ordinal);
        quiet = new(this.limits.MaxEntries, this.limits.MaxEntries, StringComparer.Ordinal);
    }

    /// <summary>The mode every record carries. Only Monitor exists until the ADR 0006 enforcer does.</summary>
    public string Mode => DecisionActions.MonitorMode;

    /// <summary>Records handed to <see cref="Observe"/>, with or without an address.</summary>
    public long Observed { get; private set; }

    /// <summary>Would-block decisions in force.</summary>
    public int ActiveCount => active.Count;

    /// <summary>Entries dropped from any map to stay within <see cref="DecisionEngineLimits"/>.</summary>
    public long Evicted => addresses.Evicted + networks.Evicted + accounts.Evicted + history.Evicted + quiet.Evicted;

    internal int TrackedAddresses => addresses.Count;
    internal int TrackedNetworks => networks.Count;
    internal int TrackedAccounts => accounts.Count;
    internal long TrackedAddressItems => addresses.Weight;
    internal int Remembered => history.Count;
    internal int Quiet => quiet.Count;

    /// <summary>
    /// Evaluates a batch of live, paired failed logons and returns the decisions it made, in order. Records
    /// without a source address count for nothing: there is nothing to decide against.
    /// </summary>
    public IReadOnlyList<DecisionRecord> Observe(IEnumerable<AuthFailure> failures, DefenseOptions options, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(failures);
        ArgumentNullException.ThrowIfNull(options);
        var evaluation = new Evaluation(this, options, now);
        foreach (var failure in failures.OrderBy(f => f.Timestamp))
        {
            Observed++;
            if (failure.Address is not null) evaluation.Add(failure);
        }
        return evaluation.Output;
    }

    /// <summary>
    /// Ends every would-block decision whose expiry has passed and returns an <c>expire</c> record for each,
    /// timestamped when it ended. Also forgets quiet periods, repeat memory and counters that can no longer
    /// matter. The collector calls it every minute.
    /// </summary>
    public IReadOnlyList<DecisionRecord> Expire(DateTimeOffset now)
    {
        var output = new List<DecisionRecord>();
        foreach (var (target, hold) in active.Where(a => a.Value.Until <= now).OrderBy(a => a.Value.Until).ToArray())
        {
            active.Remove(target);
            output.Add(Ended(target, hold, hold.Until, $"would-block for {Text(hold.Duration)} reached its expiry"));
        }
        foreach (var (key, _) in quiet.Items.Where(i => i.Value.Until <= now).ToArray()) quiet.Remove(key);
        foreach (var (key, _) in history.Items.Where(i => now - i.Value.Until > RepeatWithin).ToArray()) history.Remove(key);
        foreach (var (key, _) in addresses.Items.Where(i => now - i.Value.LastSeen > StaleAfter).ToArray()) addresses.Remove(key);
        foreach (var (key, _) in networks.Items.Where(i => now - i.Value.LastSeen > StaleAfter).ToArray()) networks.Remove(key);
        foreach (var (key, _) in accounts.Items.Where(i => now - i.Value.LastSeen > StaleAfter).ToArray()) accounts.Remove(key);
        return output;
    }

    /// <summary>
    /// Ends every decision in force because the process that made it is stopping, which is when a real
    /// block would end (ADR 0006, section 2). Returns an <c>expire</c> record for each.
    /// </summary>
    public IReadOnlyList<DecisionRecord> EndAll(DateTimeOffset now)
    {
        var output = active.OrderBy(a => a.Value.Until)
            .Select(a => Ended(a.Key, a.Value, now, "ended with the process that made it; a decision never outlives it"))
            .ToArray();
        active.Clear();
        return output;
    }

    private DecisionRecord Ended(string target, Hold hold, DateTimeOffset at, string why) =>
        new(at, DecisionActions.Expire, target, hold.RuleId, Mode,
            $"{why} (decided {hold.Decided.ToUniversalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC)", null, null);

    /// <summary>"10 minutes", "60 minutes", "6 hours", "7 days" - whole units only; minutes up to two hours, as the settings are written.</summary>
    internal static string Text(TimeSpan span) =>
        span >= TimeSpan.FromDays(1) && span.Ticks % TimeSpan.TicksPerDay == 0 ? Plural((int)span.TotalDays, "day")
        : span >= TimeSpan.FromHours(2) && span.Ticks % TimeSpan.TicksPerHour == 0 ? Plural((int)span.TotalHours, "hour")
        : Plural((int)Math.Max(1, Math.Round(span.TotalMinutes)), "minute");

    /// <summary>The time a rule's evidence spanned: "under a minute", "4 minutes".</summary>
    private static string Spanned(TimeSpan span) =>
        span < TimeSpan.FromMinutes(1) ? "under a minute" : Plural((int)Math.Floor(span.TotalMinutes), "minute");

    private static string Plural(int value, string unit) =>
        value.ToString(CultureInfo.InvariantCulture) + " " + unit + (value == 1 ? "" : "s");

    private static string Threshold(RuleSettings rule) =>
        $"threshold {rule.Count.ToString(CultureInfo.InvariantCulture)} in {Text(rule.Window)}";

    /// <summary>One <see cref="Observe"/> call: the settings, the time, and at most one read of the host's facts.</summary>
    private sealed class Evaluation(DecisionEngine engine, DefenseOptions options, DateTimeOffset now)
    {
        private AddressProtection.Pass? pass;

        internal List<DecisionRecord> Output { get; } = [];

        internal void Add(AuthFailure failure)
        {
            var address = AddressRanges.Canonical(failure.Address!);
            var addressText = address.ToString();
            var network = AddressRanges.NetworkOf(address);
            var networkText = network.ToString();
            var at = failure.Timestamp;

            // An enforced block would have dropped this attempt before it reached the log.
            if (Blocked(addressText, at) || Blocked(networkText, at)) return;

            if (!Quiet(addressText, at)) Address(failure, address, addressText, at);
            if (!Quiet(networkText, at)) Network(failure, network, networkText, addressText, at);
            if (failure.Account.Length > 0 && ExistingAccountReasons.Contains(failure.Reason)) Account(failure, addressText, at);
        }

        private void Address(AuthFailure failure, IPAddress address, string key, DateTimeOffset at)
        {
            var state = engine.addresses.Touch(key, () => new AddressState());
            state.LastSeen = at;
            var failures = options.RepeatedFailures;
            var names = options.NonexistentAccounts;

            state.Failures.Enqueue(at);
            while (state.Failures.Count > 0 && state.Failures.Peek() <= at - failures.Window) state.Failures.Dequeue();
            while (state.Failures.Count > failures.Count) state.Failures.Dequeue();

            if (failure.Reason == "unknown-account" && failure.Account.Length > 0)
                state.Names[StringComparer.OrdinalIgnoreCase.GetHashCode(failure.Account)] = at;
            foreach (var old in state.Names.Where(n => n.Value <= at - names.Window).Select(n => n.Key).ToArray()) state.Names.Remove(old);

            // The guessing rule first: it is the faster one and lasts longer.
            if (state.Names.Count >= names.Count)
            {
                var span = at - state.Names.Values.Min();
                engine.addresses.Remove(key);
                Decide(AddressRanges.Single(address), key, DecisionRules.NonexistentAccounts, names, failure.Channel,
                    $"{state.Names.Count.ToString(CultureInfo.InvariantCulture)} nonexistent account names in {Spanned(span)} ({Threshold(names)})");
                return;
            }
            if (state.Failures.Count >= failures.Count)
            {
                var span = at - state.Failures.Peek();
                engine.addresses.Remove(key);
                Decide(AddressRanges.Single(address), key, DecisionRules.RepeatedFailures, failures, failure.Channel,
                    $"{state.Failures.Count.ToString(CultureInfo.InvariantCulture)} failed logons in {Spanned(span)} ({Threshold(failures)})");
                return;
            }
            engine.addresses.Reweigh(key, state.Failures.Count + state.Names.Count);
        }

        private void Network(AuthFailure failure, IPNetwork network, string key, string member, DateTimeOffset at)
        {
            var rule = options.Network;
            var set = engine.networks.Touch(key, () => new MemberSet());
            set.Add(member, at, rule.Window);
            if (set.Members.Count >= rule.Count)
            {
                var span = at - set.Members.Values.Min();
                var count = set.Members.Count;
                engine.networks.Remove(key);
                Decide(network, key, DecisionRules.Network, rule, failure.Channel,
                    $"{count.ToString(CultureInfo.InvariantCulture)} different addresses of this network failed in {Spanned(span)} ({Threshold(rule)})");
                return;
            }
            engine.networks.Reweigh(key, set.Members.Count);
        }

        private void Account(AuthFailure failure, string member, DateTimeOffset at)
        {
            var rule = options.SharedAccount;
            var set = engine.accounts.Touch(failure.Account, () => new MemberSet());
            if (set.QuietUntil > at)
            {
                set.LastSeen = at;
                return;
            }
            set.Add(member, at, rule.Window);
            if (set.Members.Count >= rule.Count)
            {
                var span = at - set.Members.Values.Min();
                // Report only. The target is the address that completed the pattern; the account is
                // deliberately not named, so no account name reaches the decisions table.
                Output.Add(new(now, DecisionActions.Report, member, DecisionRules.SharedAccount, engine.Mode,
                    $"one existing account failed from {set.Members.Count.ToString(CultureInfo.InvariantCulture)} different addresses in " +
                    $"{Spanned(span)} ({Threshold(rule)}); report only, the account is not named here", failure.Channel, null));
                set.Members.Clear();
                set.QuietUntil = at + rule.Window;
            }
            engine.accounts.Reweigh(failure.Account, set.Members.Count);
        }

        private void Decide(IPNetwork target, string key, string ruleId, RuleSettings rule, string channel, string trigger)
        {
            pass ??= engine.protection.Begin(options);
            var check = pass.Check(target);
            if (check.Verdict == ProtectionVerdict.Protected)
            {
                var until = now + rule.Duration;
                engine.quiet.Touch(key, () => new Hold()).Set(ruleId, now, rule.Duration, until);
                Output.Add(new(now, DecisionActions.Protected, key, ruleId, engine.Mode, $"{trigger}; protected: {check.Reason}", channel, until));
                return;
            }
            if (check.Verdict == ProtectionVerdict.Refused)
            {
                Refuse(key, ruleId, rule, channel, $"{trigger}; refused: {check.Reason}");
                return;
            }
            if (engine.active.Count >= engine.limits.MaxActive)
            {
                Refuse(key, ruleId, rule, channel,
                    $"{trigger}; refused: {engine.limits.MaxActive.ToString("N0", CultureInfo.InvariantCulture)} decisions are already active");
                return;
            }

            var duration = rule.Duration > MaxDuration ? MaxDuration : rule.Duration;
            var escalated = "";
            if (engine.history.TryGet(key, out var previous) && now - previous.Until <= RepeatWithin)
            {
                var doubled = previous.Duration * 2;
                if (doubled > duration) duration = doubled > MaxDuration ? MaxDuration : doubled;
                if (duration != rule.Duration)
                    escalated = $"; a repeat within 7 days: {Text(duration)}, twice the previous {Text(previous.Duration)}" +
                        (doubled > MaxDuration ? ", capped at 7 days" : "");
            }
            var expires = now + duration;
            engine.history.Touch(key, () => new Previous()).Set(now, duration);
            engine.active[key] = new Hold().Set(ruleId, now, duration, expires);
            Output.Add(new(now, DecisionActions.WouldBlock, key, ruleId, engine.Mode, trigger + escalated, channel, expires));
        }

        /// <summary>
        /// Records the refusal and keeps the target quiet for one window, so a fact that stays unreadable
        /// produces one record per window rather than one per attempt.
        /// </summary>
        private void Refuse(string key, string ruleId, RuleSettings rule, string channel, string reason)
        {
            engine.quiet.Touch(key, () => new Hold()).Set(ruleId, now, rule.Duration, now + rule.Window);
            Output.Add(new(now, DecisionActions.Refused, key, ruleId, engine.Mode, reason, channel, null));
        }

        private bool Blocked(string key, DateTimeOffset at)
        {
            if (!engine.active.TryGetValue(key, out var hold)) return false;
            if (at < hold.Until) return true;
            // Its expiry passed before this attempt and the minute's Expire has not run yet.
            engine.active.Remove(key);
            Output.Add(engine.Ended(key, hold, hold.Until, $"would-block for {Text(hold.Duration)} reached its expiry"));
            return false;
        }

        private bool Quiet(string key, DateTimeOffset at)
        {
            if (!engine.quiet.TryGet(key, out var hold)) return false;
            if (at < hold.Until) return true;
            engine.quiet.Remove(key);
            return false;
        }
    }

    private sealed class AddressState
    {
        internal Queue<DateTimeOffset> Failures { get; } = new();

        /// <summary>Nonexistent names by hash: counting distinct names needs no attacker text in memory.</summary>
        internal Dictionary<int, DateTimeOffset> Names { get; } = [];

        internal DateTimeOffset LastSeen { get; set; }
    }

    private sealed class MemberSet
    {
        internal Dictionary<string, DateTimeOffset> Members { get; } = new(StringComparer.Ordinal);

        internal DateTimeOffset LastSeen { get; set; }

        internal DateTimeOffset QuietUntil { get; set; }

        internal void Add(string member, DateTimeOffset at, TimeSpan window)
        {
            LastSeen = at;
            Members[member] = at;
            foreach (var old in Members.Where(m => m.Value <= at - window).Select(m => m.Key).ToArray()) Members.Remove(old);
        }
    }

    /// <summary>The last would-block decision about a target: a repeat within 7 days of its end doubles the next.</summary>
    private sealed class Previous
    {
        internal DateTimeOffset Until { get; private set; }

        internal TimeSpan Duration { get; private set; }

        internal Previous Set(DateTimeOffset at, TimeSpan duration)
        {
            Until = at + duration;
            Duration = duration;
            return this;
        }
    }

    private sealed class Hold
    {
        internal string RuleId { get; private set; } = "";

        internal DateTimeOffset Decided { get; private set; }

        internal TimeSpan Duration { get; private set; }

        internal DateTimeOffset Until { get; private set; }

        internal Hold Set(string ruleId, DateTimeOffset decided, TimeSpan duration, DateTimeOffset until)
        {
            RuleId = ruleId;
            Decided = decided;
            Duration = duration;
            Until = until;
            return this;
        }
    }
}

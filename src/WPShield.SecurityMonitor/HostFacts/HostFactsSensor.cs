using Microsoft.Extensions.Logging;
using WPShield.Evidence;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Takes the host-fact snapshots of ADR 0013 on their cadences, inside the evidence collector.
/// </summary>
/// <remarks>
/// <para>
/// <b>Reads run in the background; only the collector's loop writes.</b> A read can take seconds (tasks,
/// signatures), and failed-logon collection must never wait for it, so each read runs on the thread pool, one
/// at a time, and the loop stores its result on a later tick. SQLite is touched by the loop thread only.
/// </para>
/// <para>
/// <b>Bounded in time.</b> A read gets <see cref="HostFacts.ReadBudget"/> through its cancellation token. One
/// that ignores it is abandoned at twice the budget and stored as <c>partial</c>, never left half-written.
/// </para>
/// <para>
/// <b>Evidence only.</b> Nothing here reaches the decision engine.
/// </para>
/// </remarks>
public sealed class HostFactsSensor
{
    private readonly ILogger logger;

    public HostFactsSensor(IHostFactSource source, ILogger logger)
    {
        Source = source ?? throw new ArgumentNullException(nameof(source));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public IHostFactSource Source { get; }

    internal ILogger Logger => logger;

    /// <summary>Runs one read in the background. Tests replace it with a synchronous runner.</summary>
    internal Func<Func<object>, Task<object>> RunInBackground { get; init; } = work => Task.Run(work);

    internal TimeSpan Budget { get; init; } = HostFacts.ReadBudget;

    internal HostFactsSession Start(EvidenceStore store, string storePath, DateTimeOffset now) => new(this, store, storePath, now);
}

/// <summary>One collector session's host facts: the schedule, the read in flight and the writer.</summary>
internal sealed class HostFactsSession
{
    private readonly HostFactsSensor owner;
    private readonly HostFactsWriter writer;
    private readonly HostFactsQueries queries;
    private readonly string storePath;
    private readonly Dictionary<string, DateTimeOffset> due = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> lastStatus = new(StringComparer.Ordinal);
    private Job? running;

    /// <summary>The jobs in priority order: what is cheap and frequent first.</summary>
    internal static readonly IReadOnlyList<string> Jobs =
    [
        HostFacts.Health, "restarts", HostFacts.Sessions, HostFacts.Ports, HostFacts.Sites, HostFacts.Posture,
        HostFacts.Inventory + "/" + HostFacts.Accounts, HostFacts.Inventory + "/" + HostFacts.Services, HostFacts.Inventory + "/" + HostFacts.Tasks
    ];

    internal HostFactsSession(HostFactsSensor owner, EvidenceStore store, string storePath, DateTimeOffset now)
    {
        this.owner = owner;
        this.storePath = storePath;
        writer = new HostFactsWriter(store);
        queries = new HostFactsQueries(store);
        // Every fact is read at start; then each on its own cadence.
        foreach (var job in Jobs) due[job] = now;
        owner.Logger.LogInformation(
            "Host facts started (ADR 0013, read-only - nothing on this server is changed). Health every {Health} min; sites, ports and " +
            "sessions every {Frequent} min; posture and inventory every {Rare} h. Snapshots go to the evidence store.",
            (int)HostFacts.HealthCadence.TotalMinutes, (int)HostFacts.SitesCadence.TotalMinutes, (int)HostFacts.PostureCadence.TotalHours);
    }

    /// <summary>The number of snapshots written by this session, for tests and the log.</summary>
    internal int Written { get; private set; }

    /// <summary>One pass: store a finished read, abandon one past its budget, start the next one due.</summary>
    public void Tick(DateTimeOffset now)
    {
        if (running is { } job)
        {
            if (job.Task.IsCompleted)
            {
                running = null;
                Complete(job, now);
            }
            else if (now - job.Started > 2 * owner.Budget)
            {
                running = null;
                job.Cancellation.Cancel();
                if (job.Name == "restarts")
                    Announce(job.Name, HostFactStatus.Partial, "time-budget", "The System log is read again on its cadence.");
                else
                    Store(Abandoned(job, now), now);
                // The task finishes on its own and is discarded.
            }
            else
            {
                if (now - job.Started > owner.Budget) job.Cancellation.Cancel();
                return;
            }
        }

        var next = Jobs.FirstOrDefault(name => due[name] <= now);
        if (next is null) return;
        due[next] = now + Cadence(next);
        StartJob(next, now);
    }

    /// <summary>Stops the read in flight; its result is discarded. Nothing is half-written.</summary>
    public void Stop()
    {
        running?.Cancellation.Cancel();
        running = null;
    }

    private static TimeSpan Cadence(string job) => job switch
    {
        "restarts" => HostFacts.RestartCadence,
        _ when job.StartsWith(HostFacts.Inventory, StringComparison.Ordinal) => HostFacts.InventoryCadence,
        _ => HostFacts.Cadence(job)
    };

    private void StartJob(string name, DateTimeOffset now)
    {
        var cancellation = new CancellationTokenSource(owner.Budget);
        var token = cancellation.Token;
        var source = owner.Source;
        Func<object> work = name switch
        {
            HostFacts.Health => () => source.ReadHealth(storePath, token),
            "restarts" => RestartWork(source, now, token),
            HostFacts.Sessions => () => source.ReadSessions(now - HostFacts.SessionWindow, token),
            HostFacts.Ports => () => source.ReadPorts(token),
            HostFacts.Sites => () => source.ReadSites(token),
            HostFacts.Posture => () => source.ReadPosture(token),
            _ => () => source.ReadInventory(name[(HostFacts.Inventory.Length + 1)..], token)
        };
        Task<object> task;
        try
        {
            task = owner.RunInBackground(work);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            task = Task.FromException<object>(exception);
        }
        running = new Job(name, now, task, cancellation);
        // A synchronous runner (tests) finishes at once; store it in the same tick.
        if (task.IsCompleted)
        {
            running = null;
            Complete(new Job(name, now, task, cancellation), now);
        }
    }

    private Func<object> RestartWork(IHostFactSource source, DateTimeOffset now, CancellationToken token)
    {
        // Later starts read only what is new, from a little before where the last read stopped, so a 1001
        // written minutes after its 41 still joins it.
        var until = writer.RestartsReadUntil();
        var since = until is null ? now - HostFacts.RestartWindow : until.Value - HostRestarts.Overlap;
        if (since < now - HostFacts.RestartWindow) since = now - HostFacts.RestartWindow;
        return () => source.ReadRestarts(since, token);
    }

    private void Complete(Job job, DateTimeOffset now)
    {
        job.Cancellation.Dispose();
        if (job.Task.IsFaulted || job.Task.IsCanceled)
        {
            var type = job.Task.Exception?.GetBaseException().GetType().Name ?? "canceled";
            owner.Logger.LogWarning("A host fact could not be read ({Job}, {ErrorType}). It is stored as unreadable and read again on its cadence.",
                job.Name, type);
            // A failed restart read must not overwrite the health snapshot: it is reported, and read again.
            if (job.Name == "restarts")
                Announce(job.Name, HostFactStatus.Unreadable, $"read-failed: {type}", "The System log is read again on its cadence.");
            else
                Store(Failed(job, now, $"read-failed: {type}"), now);
            return;
        }
        switch (job.Task.Result)
        {
            case HostRestartReading restarts:
                StoreRestarts(restarts);
                break;
            case HostInventoryReading inventory:
                StoreInventory(inventory, now);
                break;
            case HostFactReading reading:
                if (reading.Fact == HostFacts.Health && reading.Value<HostHealth>() is { } health) writer.RecordHealth(health, reading.TakenAt);
                Store(reading, now);
                break;
        }
    }

    private void StoreRestarts(HostRestartReading reading)
    {
        if (reading.Status is HostFactStatus.Ok or HostFactStatus.Partial)
        {
            var restarts = HostRestarts.Group(reading.Records);
            var added = writer.RecordRestarts(restarts);
            writer.SetRestartsReadUntil(reading.TakenAt);
            if (added > 0)
            {
                // Codes only: a bugcheck code and its name are not host details.
                owner.Logger.LogWarning(
                    "Unexpected restarts recorded: {Added}. Bugcheck codes: {Codes}. 'wpshield host health' lists them.",
                    added, string.Join(", ", restarts.Select(r => r.BugCheck ?? "none").Distinct(StringComparer.Ordinal)));
            }
        }
        Announce("restarts", reading.Status, reading.Reason, reading.Remedy);
    }

    private void StoreInventory(HostInventoryReading inventory, DateTimeOffset now)
    {
        var reading = inventory.Reading;
        if (reading.Kind == HostFacts.Accounts)
        {
            IReadOnlyList<string>? attempted = null;
            try
            {
                attempted = queries.AttemptedAccountNames(now - HostFacts.AttemptWindow);
            }
            catch (Exception exception) when (exception is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
            {
                owner.Logger.LogDebug("The attempted account names could not be read ({ErrorType}).", exception.GetType().Name);
            }
            reading = inventory.WithFullNameIndicator(attempted);
        }

        if (reading.Payload is not null && reading.Kind is { } kind && queries.Latest(HostFacts.Inventory, kind) is { Payload: not null } previous)
        {
            var changes = InventoryDiff.Compare(kind, Views(previous), Views(reading));
            if (changes.Count > 0)
            {
                var (stored, overflow) = writer.RecordInventoryChanges(kind, changes, reading.TakenAt);
                owner.Logger.LogInformation(
                    "Inventory changes recorded ({Kind}): Added={Added} Removed={Removed} Changed={Changed} Stored={Stored} Overflow={Overflow}. " +
                    "'wpshield host inventory {Kind}' shows the current state.",
                    kind, changes.Count(c => c.Change == "added"), changes.Count(c => c.Change == "removed"),
                    changes.Count(c => c.Change == "changed"), stored, overflow, kind);
            }
        }
        Store(reading, now);
    }

    private static IEnumerable<InventoryItemView> Views(HostFactReading reading) => reading.Kind switch
    {
        HostFacts.Accounts when reading.Value<HostAccounts>() is { } accounts => InventoryDiff.Views(accounts),
        HostFacts.Services when reading.Value<HostServices>() is { } services => InventoryDiff.Views(services),
        HostFacts.Tasks when reading.Value<HostTasks>() is { } tasks => InventoryDiff.Views(tasks),
        _ => []
    };

    private void Store(HostFactReading reading, DateTimeOffset now)
    {
        try
        {
            var stored = writer.Write(reading);
            Written++;
            Announce(stored.Kind is null ? stored.Fact : $"{stored.Fact}/{stored.Kind}", stored.Status, stored.Reason, stored.Remedy);
            if (stored.Fact is HostFacts.Posture or HostFacts.Inventory && stored.Status == HostFactStatus.Ok)
                owner.Logger.LogInformation("Host fact recorded: {Fact}{Kind}.", stored.Fact, stored.Kind is null ? "" : "/" + stored.Kind);
        }
        catch (ArgumentException exception)
        {
            // A reader broke the contract (unknown status, no remedy): say so; the collector carries on.
            owner.Logger.LogError("A host fact was refused by the store ({Fact}): {Problem}", reading.Fact, exception.Message);
        }
    }

    /// <summary>A fact that is not ok is reported once when its status changes, not on every snapshot.</summary>
    private void Announce(string name, string status, string? reason, string? remedy)
    {
        if (lastStatus.TryGetValue(name, out var previous) && previous == status) return;
        lastStatus[name] = status;
        if (status == HostFactStatus.Ok)
        {
            if (previous is not null) owner.Logger.LogInformation("Host fact {Fact} is read again.", name);
            return;
        }
        owner.Logger.LogWarning("Host fact {Fact} is {Status} ({Reason}). {Remedy}", name, status, reason ?? "no reason given",
            remedy ?? "");
    }

    private static HostFactReading Failed(Job job, DateTimeOffset now, string reason)
    {
        var (fact, kind) = FactOf(job.Name);
        return HostFactReading.Failed(fact, kind, now, HostFactStatus.Unreadable, reason,
            "Run 'wpshield host --live' elevated to see the error; the collector reads it again on its cadence.");
    }

    private HostFactReading Abandoned(Job job, DateTimeOffset now)
    {
        var (fact, kind) = FactOf(job.Name);
        owner.Logger.LogWarning("A host fact read took longer than its budget ({Job}, {Seconds} s) and was abandoned. It is stored as partial.",
            job.Name, (int)(2 * owner.Budget).TotalSeconds);
        return HostFactReading.Failed(fact, kind, now, HostFactStatus.Partial, "time-budget",
            "The read was stopped at its time budget so the collector stays light; it runs again on its cadence.");
    }

    private static (string Fact, string? Kind) FactOf(string job) => job switch
    {
        _ when job.StartsWith(HostFacts.Inventory + "/", StringComparison.Ordinal) => (HostFacts.Inventory, job[(HostFacts.Inventory.Length + 1)..]),
        _ => (job, null)
    };

    private sealed record Job(string Name, DateTimeOffset Started, Task<object> Task, CancellationTokenSource Cancellation);
}

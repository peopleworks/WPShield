namespace WPShield.NetworkFilter;

/// <summary>
/// What WPShield asks of WinDivert, and nothing more. The production implementation is
/// <see cref="WinDivertDriver"/>; tests substitute a fake so that every safety property in ADR 0006
/// can be asserted without a driver.
/// </summary>
public interface IDivertDriver
{
    /// <summary>Opens a handle. Throws <see cref="DivertDriverException"/> when the driver refuses.</summary>
    IDivertHandle Open(string filter, DivertHandleKind kind, short priority);

    /// <summary>Compiles a filter without opening anything. Needs neither elevation nor the driver.</summary>
    FilterCompileResult Compile(string filter);

    /// <summary>
    /// Evaluates a filter against one packet, as if it had arrived inbound on a non-loopback interface.
    /// Needs neither elevation nor the driver.
    /// </summary>
    bool Evaluate(string filter, byte[] packet, bool isIpv6);
}

/// <summary>The only two kinds of handle WPShield ever opens.</summary>
public enum DivertHandleKind
{
    /// <summary>
    /// <c>SNIFF | RECV_ONLY</c>: receives copies of matching packets. The originals continue
    /// untouched, so this handle can never delay or lose traffic.
    /// </summary>
    Observe,

    /// <summary>
    /// <c>DROP</c>: the driver silently drops every matching packet in the kernel. Nothing is ever
    /// received from this handle and nothing is ever reinjected.
    /// </summary>
    Drop,
}

/// <summary>An open WinDivert handle. Disposing it removes its filter from the driver.</summary>
public interface IDivertHandle : IDisposable
{
    /// <summary>
    /// Blocks until a packet arrives and returns its length, or returns 0 once
    /// <see cref="Shutdown"/> has been called and nothing is left to read.
    /// </summary>
    int Receive(byte[] buffer);

    /// <summary>Unblocks a pending <see cref="Receive"/>. Safe to call from another thread.</summary>
    void Shutdown();
}

/// <summary>The outcome of compiling a filter.</summary>
public sealed record FilterCompileResult(bool Succeeded, string? Error, int ErrorPosition)
{
    public static FilterCompileResult Success { get; } = new(true, null, 0);
}

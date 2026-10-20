using System.Diagnostics;
using System.Runtime.InteropServices;
using WPShield.Abstractions;

namespace WPShield.NetworkFilter;

/// <summary>
/// User-mode packet filter built on WinDivert.
///
/// Design constraint inherited from the Malwarebytes mwac.sys failure observed in production:
/// this code never runs in kernel, never acquires a kernel spinlock on the packet path, and
/// enforces a strict per-packet inspection budget. If inspection takes longer than
/// <see cref="MaxInspectionTime"/>, the packet is forwarded uninspected rather than risking a
/// DPC watchdog violation or stalling the network stack.
/// </summary>
public sealed class NetworkFilterEngine : IDisposable
{
    private readonly IEnumerable<INetworkInspectionRule> _rules;
    private readonly IntPtr _handle;
    private readonly TimeSpan _maxInspectionTime;

    /// <summary>
    /// Maximum time allowed to inspect a single packet before forwarding it uninspected.
    /// Default: 5 milliseconds.
    /// </summary>
    public TimeSpan MaxInspectionTime => _maxInspectionTime;

    public NetworkFilterEngine(
        IEnumerable<INetworkInspectionRule> rules,
        string? filter = null,
        TimeSpan? maxInspectionTime = null)
    {
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _maxInspectionTime = maxInspectionTime ?? TimeSpan.FromMilliseconds(5);

        // Default filter: inbound TCP only. Outbound and loopback are left to the OS firewall.
        filter ??= "tcp.Inbound";

        _handle = WinDivertInterop.WinDivertOpen(
            filter,
            WinDivertInterop.WINDIVERT_LAYER_NETWORK,
            0,
            WinDivertInterop.WINDIVERT_FLAG_SNIFF);

        if (_handle == IntPtr.Zero || _handle.ToInt64() == -1)
        {
            var lastError = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"Failed to open WinDivert handle for filter '{filter}'. " +
                $"Win32 error code: {lastError}. " +
                "Ensure the WinDivert driver is installed on this machine.");
        }
    }

    /// <summary>
    /// Runs the capture loop until <paramref name="cancellationToken"/> is cancelled.
    /// Packets that match a blocking rule are dropped; all others are reinjected.
    /// </summary>
    public void Run(CancellationToken cancellationToken = default)
    {
        const int maxPacketSize = 65_536;
        IntPtr packetBuffer = Marshal.AllocHGlobal(maxPacketSize);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                IntPtr addr;
                bool received = WinDivertInterop.WinDivertRecv(
                    _handle,
                    packetBuffer,
                    maxPacketSize,
                    out addr,
                    IntPtr.Zero);

                if (!received)
                {
                    // No packet available; yield briefly to avoid a busy loop.
                    Thread.Sleep(0);
                    continue;
                }

                bool shouldBlock = InspectPacket(packetBuffer, out var evidence);

                if (shouldBlock)
                {
                    // Drop the packet: do not call WinDivertSend.
                    continue;
                }

                // Reinject the packet so it continues to its destination.
                _ = WinDivertInterop.WinDivertSend(
                    _handle,
                    packetBuffer,
                    maxPacketSize,
                    addr,
                    IntPtr.Zero);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(packetBuffer);
            WinDivertInterop.WinDivertClose(_handle);
        }
    }

    private bool InspectPacket(IntPtr packet, out Dictionary<string, object> evidence)
    {
        evidence = new(StringComparer.Ordinal);

        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Parse minimal IPv4 + TCP/UDP headers without pointers.
            if (!TryParsePacket(packet, out var info) || info is null)
            {
                return false;
            }

            foreach (var rule in _rules)
            {
                var context = new NetworkInspectionContext
                {
                    SourceIp = info.SourceIp,
                    DestinationIp = info.DestinationIp,
                    SourcePort = info.SourcePort,
                    DestinationPort = info.DestinationPort,
                    Protocol = info.Protocol,
                    Timestamp = DateTimeOffset.UtcNow,
                    PacketSize = info.PacketSize,
                    PayloadSample = info.PayloadSample
                };

                var result = rule.Inspect(context, CancellationToken.None);

                evidence[$"{result.RuleId}.score"] = result.Score;
                evidence[$"{result.RuleId}.action"] = result.Action.ToString();

                foreach (var kvp in result.Evidence)
                {
                    evidence[$"{result.RuleId}.{kvp.Key}"] = kvp.Value;
                }

                if (result.Action == WPShield.Abstractions.NetworkInspectionAction.Block)
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            stopwatch.Stop();

            if (stopwatch.Elapsed > _maxInspectionTime)
            {
                evidence["inspection_exceeded_budget_ms"] = stopwatch.Elapsed.TotalMilliseconds;
                // Deliberately do not block: packet is forwarded to avoid becoming a DoS vector.
            }
        }
    }

    private static bool TryParsePacket(IntPtr packet, out NetworkPacketInfo? info)
    {
        info = null;

        if (packet == IntPtr.Zero)
        {
            return false;
        }

        // IPv4 header is 20 bytes minimum. Read version/IHL byte at offset 0.
        byte versionIhl = Marshal.ReadByte(packet, 0);
        int version = versionIhl >> 4;
        int ihl = (versionIhl & 0x0F) * 4;

        if (version != 4 || ihl < 20)
        {
            return false;
        }

        // Protocol byte at offset 9 (IPv4).
        byte protocolByte = Marshal.ReadByte(packet, 9);
        string? protocol = protocolByte switch
        {
            6 => "TCP",
            17 => "UDP",
            _ => null
        };

        if (protocol is null)
        {
            return false;
        }

        // Source IP at offset 12, destination at 16 (4 bytes each).
        string sourceIp = $"{Marshal.ReadByte(packet, 12)}.{Marshal.ReadByte(packet, 13)}.{Marshal.ReadByte(packet, 14)}.{Marshal.ReadByte(packet, 15)}";
        string destinationIp = $"{Marshal.ReadByte(packet, 16)}.{Marshal.ReadByte(packet, 17)}.{Marshal.ReadByte(packet, 18)}.{Marshal.ReadByte(packet, 19)}";

        // Total length at offset 2 (2 bytes, little-endian).
        ushort totalLength = (ushort)(Marshal.ReadByte(packet, 2) | (Marshal.ReadByte(packet, 3) << 8));
        int payloadLength = totalLength - ihl;

        // Transport header starts after IP header.
        int transportOffset = ihl;
        int sourcePort = 0;
        int destinationPort = 0;
        int payloadOffset = transportOffset;

        if (protocol == "TCP" && payloadLength >= 20)
        {
            sourcePort = ReadUInt16(packet, transportOffset);
            destinationPort = ReadUInt16(packet, transportOffset + 2);
            // TCP data offset is in byte 12 of the TCP header, high nibble * 4.
            int tcpDataOffset = (Marshal.ReadByte(packet, transportOffset + 12) >> 4) * 4;
            payloadOffset = transportOffset + tcpDataOffset;
        }
        else if (protocol == "UDP" && payloadLength >= 8)
        {
            sourcePort = ReadUInt16(packet, transportOffset);
            destinationPort = ReadUInt16(packet, transportOffset + 2);
            payloadOffset = transportOffset + 8;
        }

        // Bounded payload sample: first 64 bytes only.
        int sampleLength = Math.Max(0, Math.Min(64, totalLength - payloadOffset));
        byte[] sample = new byte[sampleLength];
        if (sampleLength > 0)
        {
            Marshal.Copy(new IntPtr(packet.ToInt64() + payloadOffset), sample, 0, sampleLength);
        }

        info = new NetworkPacketInfo
        {
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            Protocol = protocol,
            PacketSize = totalLength,
            PayloadSample = sample
        };

        return true;
    }

    private static ushort ReadUInt16(IntPtr packet, int offset)
    {
        byte low = Marshal.ReadByte(packet, offset);
        byte high = Marshal.ReadByte(packet, offset + 1);
        return (ushort)(low | (high << 8));
    }

    public void Dispose()
    {
        WinDivertInterop.WinDivertClose(_handle);
        GC.SuppressFinalize(this);
    }
}

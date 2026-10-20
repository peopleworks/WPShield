namespace WPShield.Abstractions;

/// <summary>
/// Recommended action for a network-level inspection finding.
/// </summary>
public enum NetworkInspectionAction
{
    /// <summary>Allow the packet to continue its normal course.</summary>
    Allow = 0,

    /// <summary>Record the finding but allow the packet (monitor mode).</summary>
    Observe = 1,

    /// <summary>Drop the packet; do not forward it.</summary>
    Block = 2
}

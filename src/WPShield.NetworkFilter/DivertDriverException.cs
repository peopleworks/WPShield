namespace WPShield.NetworkFilter;

/// <summary>
/// WinDivert refused. The message is written for the operator: it names what is missing and what to
/// do about it, because the alternative is a Win32 error number on a server that is having a bad day.
/// </summary>
public sealed class DivertDriverException : Exception
{
    public const int ErrorFileNotFound = 2;
    public const int ErrorAccessDenied = 5;
    public const int ErrorInvalidParameter = 87;
    public const int ErrorNoData = 232;
    public const int ErrorInvalidImageHash = 577;
    public const int ErrorServiceDoesNotExist = 1060;
    public const int ErrorDriverBlocked = 1275;

    public DivertDriverException(string message, int win32Error)
        : base(message)
    {
        Win32Error = win32Error;
    }

    public DivertDriverException()
    {
    }

    public DivertDriverException(string message)
        : base(message)
    {
    }

    public DivertDriverException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The Win32 error WinDivert reported, or 0 when none applies.</summary>
    public int Win32Error { get; }

    /// <summary>Turns a WinDivertOpen failure into a sentence an operator can act on.</summary>
    public static DivertDriverException FromOpenFailure(int win32Error) => new(
        win32Error switch
        {
            ErrorServiceDoesNotExist =>
                "The WinDivert driver is not installed, and WPShield does not install drivers as a side " +
                "effect. Re-run with --install-driver to let WinDivert install its driver service, or " +
                "install it yourself. Undo it later with 'sc stop WinDivert' and 'sc delete WinDivert'.",
            ErrorAccessDenied =>
                "WinDivert refused: the process is not elevated. Run the command as Administrator.",
            ErrorFileNotFound =>
                "WinDivert64.sys was not found next to WinDivert.dll. Both files come from the same " +
                "WinDivert 2.2.2 release and must sit in the WPShield program directory.",
            ErrorInvalidImageHash or ErrorDriverBlocked =>
                "Windows refused to load the WinDivert driver (signature or driver block policy). Use the " +
                "unmodified files from the official WinDivert 2.2.2 release, and check whether security " +
                "software or the vulnerable-driver blocklist is blocking it.",
            ErrorInvalidParameter =>
                "WinDivert rejected a filter WPShield generated. This is a WPShield defect: the filter " +
                "passed its own compile check first. Run 'wpshield network-filter --check' and report it.",
            _ => $"WinDivert could not open a handle (Win32 error {win32Error}).",
        },
        win32Error);
}

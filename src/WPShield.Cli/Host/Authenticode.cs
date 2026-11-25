using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using WPShield.Evidence;

namespace WPShield.Cli.Host;

/// <summary>The result of one signature check.</summary>
/// <param name="Status"><c>signed</c>, <c>unsigned</c> or <c>not-checked</c>.</param>
/// <param name="Signer">The signing certificate's simple name, cleaned; <see langword="null"/> when unsigned.</param>
/// <param name="Microsoft">Whether the signer is Microsoft Corporation.</param>
internal sealed record SignatureResult(string Status, string? Signer, bool Microsoft)
{
    public static readonly SignatureResult NotChecked = new(HostSignature.NotChecked, null, false);
    public static readonly SignatureResult Unsigned = new(HostSignature.Unsigned, null, false);
}

/// <summary>
/// Authenticode checks for the host inventory (ADR 0013, section 1.3): embedded signatures and the catalog
/// signatures most Windows binaries carry, through <c>WinVerifyTrust</c>, read-only.
/// </summary>
/// <remarks>
/// <para>
/// <b>Bounded and cached.</b> Results are cached by path, size and last-write time for the life of the process,
/// and each snapshot verifies at most <see cref="HostFacts.MaxSignatureChecks"/> binaries; the rest stay
/// <c>not-checked</c> until the next snapshot. Revocation is not checked: that would make the collector call out
/// to the network, and the question here is "Microsoft's or not", not "trusted for code loading".
/// </para>
/// <para>
/// A signature that does not verify reads as <c>unsigned</c>: an invalid signature is no evidence of who made the file.
/// </para>
/// </remarks>
internal sealed class Authenticode
{
    private const int MaxCached = 20_000;
    private readonly Dictionary<(string Path, long Size, DateTime Written), SignatureResult> cache = new();
    private readonly object gate = new();

    /// <summary>One snapshot's budget of checks that miss the cache.</summary>
    internal sealed class Budget(int checks)
    {
        public int Remaining { get; private set; } = checks;

        public int NotChecked { get; private set; }

        public bool TryTake()
        {
            if (Remaining <= 0)
            {
                NotChecked++;
                return false;
            }
            Remaining--;
            return true;
        }
    }

    public SignatureResult Check(string? path, Budget budget)
    {
        if (string.IsNullOrWhiteSpace(path)) return SignatureResult.NotChecked;
        FileInfo file;
        try
        {
            file = new FileInfo(Environment.ExpandEnvironmentVariables(path));
            if (!file.Exists) return SignatureResult.NotChecked;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return SignatureResult.NotChecked;
        }
        var key = (file.FullName.ToUpperInvariant(), file.Length, file.LastWriteTimeUtc);
        lock (gate)
        {
            if (cache.TryGetValue(key, out var cached)) return cached;
        }
        if (!budget.TryTake()) return SignatureResult.NotChecked;
        var result = Verify(file.FullName);
        lock (gate)
        {
            if (cache.Count >= MaxCached) cache.Clear();
            cache[key] = result;
        }
        return result;
    }

    internal static SignatureResult Verify(string path)
    {
        try
        {
            var embedded = VerifyFile(path);
            if (embedded is not null) return embedded;
            return VerifyCatalog(path) ?? SignatureResult.Unsigned;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DllNotFoundException
            or EntryPointNotFoundException or System.Security.Cryptography.CryptographicException)
        {
            return SignatureResult.NotChecked;
        }
    }

    /// <summary>The embedded signature, or <see langword="null"/> when the file carries none.</summary>
    private static SignatureResult? VerifyFile(string path)
    {
        var filePath = Marshal.StringToHGlobalUni(path);
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(new WinTrustFileInfo
            {
                Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = filePath
            }, info, false);
            var data = NewData(ChoiceFile, info);
            var status = Trust(ref data, out var signer);
            if (status == TrustNoSignature || status == TrustSubjectFormUnknown || status == TrustProviderUnknown) return null;
            return status == 0 ? signer : SignatureResult.Unsigned;
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(filePath);
        }
    }

    /// <summary>The catalog signature Windows binaries carry, or <see langword="null"/> when no catalog lists the file.</summary>
    private static SignatureResult? VerifyCatalog(string path)
    {
        foreach (var algorithm in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
            try
            {
                using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
                if (size == 0 || size > 128) continue;
                var hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) continue;
                var previous = IntPtr.Zero;
                var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
                if (catalog == IntPtr.Zero) continue;
                try
                {
                    var catalogInfo = new CatalogInfo { Size = (uint)Marshal.SizeOf<CatalogInfo>() };
                    if (!CryptCATCatalogInfoFromContext(catalog, ref catalogInfo, 0)) continue;
                    return VerifyAgainstCatalog(path, catalogInfo.File, hash, admin);
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
        return null;
    }

    private static SignatureResult VerifyAgainstCatalog(string path, string catalogFile, byte[] hash, IntPtr admin)
    {
        var tag = Marshal.StringToHGlobalUni(Convert.ToHexString(hash));
        var catalogPath = Marshal.StringToHGlobalUni(catalogFile);
        var memberPath = Marshal.StringToHGlobalUni(path);
        var hashBuffer = Marshal.AllocHGlobal(hash.Length);
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        try
        {
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);
            Marshal.StructureToPtr(new WinTrustCatalogInfo
            {
                Size = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                CatalogFilePath = catalogPath,
                MemberTag = tag,
                MemberFilePath = memberPath,
                CalculatedFileHash = hashBuffer,
                CalculatedFileHashSize = (uint)hash.Length,
                CatalogAdmin = admin
            }, info, false);
            var data = NewData(ChoiceCatalog, info);
            return Trust(ref data, out var signer) == 0 ? signer : SignatureResult.Unsigned;
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            Marshal.FreeHGlobal(hashBuffer);
            Marshal.FreeHGlobal(memberPath);
            Marshal.FreeHGlobal(catalogPath);
            Marshal.FreeHGlobal(tag);
        }
    }

    private static WinTrustData NewData(uint choice, IntPtr info) => new()
    {
        Size = (uint)Marshal.SizeOf<WinTrustData>(),
        UiChoice = UiNone,
        RevocationChecks = RevokeNone,
        UnionChoice = choice,
        Info = info,
        StateAction = StateActionVerify,
        ProviderFlags = RevocationCheckNone | CacheOnlyUrlRetrieval
    };

    /// <summary>Verifies, reads the signer from the verified state, and always closes the state.</summary>
    private static int Trust(ref WinTrustData data, out SignatureResult signer)
    {
        var action = GenericVerifyV2;
        var status = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        signer = SignatureResult.Unsigned;
        try
        {
            if (status == 0) signer = Signer(data.StateData);
        }
        finally
        {
            data.StateAction = StateActionClose;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }
        return status;
    }

    private static SignatureResult Signer(IntPtr state)
    {
        var provider = WTHelperProvDataFromStateData(state);
        if (provider == IntPtr.Zero) return new(HostSignature.Signed, null, false);
        var signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if (signer == IntPtr.Zero) return new(HostSignature.Signed, null, false);
        // CRYPT_PROVIDER_SGNR: cbStruct, sftVerifyAsOf (FILETIME), csCertChain, then pasCertChain at offset 16.
        var chain = Marshal.ReadIntPtr(signer, 16);
        if (chain == IntPtr.Zero) return new(HostSignature.Signed, null, false);
        // CRYPT_PROVIDER_CERT: cbStruct, then pCert at the next pointer boundary.
        var context = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (context == IntPtr.Zero) return new(HostSignature.Signed, null, false);
        using var certificate = new X509Certificate2(context);
        var name = HostFacts.Clean(certificate.GetNameInfo(X509NameType.SimpleName, false));
        var microsoft = certificate.Subject.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
        return new(HostSignature.Signed, name.Length == 0 ? null : name, microsoft);
    }

    // ---------------------------------------------------------------------------------------------
    //  Interop
    // ---------------------------------------------------------------------------------------------

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint UiNone = 2;
    private const uint RevokeNone = 0;
    private const uint ChoiceFile = 1;
    private const uint ChoiceCatalog = 2;
    private const uint StateActionVerify = 1;
    private const uint StateActionClose = 2;
    private const uint RevocationCheckNone = 0x10;
    private const uint CacheOnlyUrlRetrieval = 0x1000;
    private const int TrustNoSignature = unchecked((int)0x800B0100);
    private const int TrustSubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustProviderUnknown = unchecked((int)0x800B0001);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Info;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustCatalogInfo
    {
        public uint Size;
        public uint CatalogVersion;
        public IntPtr CatalogFilePath;
        public IntPtr MemberTag;
        public IntPtr MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public IntPtr CatalogContext;
        public IntPtr CatalogAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string File;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string? hashAlgorithm, IntPtr strongHashPolicy,
        uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint size, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, ref IntPtr previous);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
}

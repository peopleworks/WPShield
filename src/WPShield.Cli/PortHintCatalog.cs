namespace WPShield.Cli;

internal static class PortHintCatalog
{
    // Bump this identifier when the assignments change so saved inventories stay interpretable.
    internal const string Version = "wpshield-iana-v1";

    // Selected entries from the IANA Service Name and Transport Protocol Port Number Registry.
    // Preserve multiple registrations for the same transport and port, including aliases.
    internal static IReadOnlyList<string> Lookup(string protocol, int port) => (protocol, port) switch
    {
        ("TCP" or "UDP", 21) => ["ftp"],
        ("TCP" or "UDP", 22) => ["ssh"],
        ("TCP" or "UDP", 25) => ["smtp"],
        ("TCP" or "UDP", 80) => ["http", "www", "www-http"],
        ("TCP" or "UDP", 110) => ["pop3"],
        ("TCP", 143) => ["imap"],
        ("TCP" or "UDP", 443) => ["https"],
        ("TCP", 465) => ["submissions", "urd"],
        ("UDP", 465) => ["igmpv3lite"],
        ("TCP" or "UDP", 500) => ["isakmp"],
        ("TCP" or "UDP", 587) => ["submission"],
        ("TCP", 993) => ["imaps"],
        ("TCP" or "UDP", 995) => ["pop3s"],
        ("TCP" or "UDP", 1433) => ["ms-sql-s"],
        ("TCP" or "UDP", 1434) => ["ms-sql-m"],
        ("TCP" or "UDP", 1723) => ["pptp"],
        ("TCP" or "UDP", 3306) => ["mysql"],
        ("TCP" or "UDP", 3389) => ["ms-wbt-server"],
        ("TCP" or "UDP", 4500) => ["ipsec-nat-t"],
        ("TCP" or "UDP", 5060) => ["sip"],
        ("TCP" or "UDP", 5061) => ["sips"],
        _ => []
    };
}

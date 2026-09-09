using System.CommandLine;
using WPShield.Cli;

// ---------------------------------------------------------------------------------------------
//  wpshield — the operator tool.
//
//  ADR 0003 moves every operator script except the triage tool here. The triage tool stays in
//  PowerShell on purpose: it runs on a host that has no WPShield installed and may be compromised,
//  where a single ASCII file that can be pasted into an RDP window is the feature.
//
//  Every verb that changes the machine takes --dry-run, and a dry run never requires elevation. The
//  point of a preview is that an operator can read exactly what a tool intends before deciding to
//  let it, and requiring administrator rights to READ that makes the preview harder to reach than
//  the thing it previews.
// ---------------------------------------------------------------------------------------------

var root = new RootCommand(
    "WPShield operator tool. Research preview: not approved for production traffic.");

root.Subcommands.Add(StatusCommand.Create());

return root.Parse(args).Invoke();

using System.Text.Json;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Rules.WordPress;

var configurationPath = args.FirstOrDefault() ?? "appsettings.json";
var json = await File.ReadAllTextAsync(configurationPath);
var configuration = JsonSerializer.Deserialize<AppConfiguration>(json, new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
}) ?? throw new InvalidOperationException("Configuration is empty.");

var resolver = new SiteResolver(configuration.Sites);
var site = resolver.Resolve("wordpress-one.example")
    ?? throw new InvalidOperationException("Example site could not be resolved.");

IInspectionRule[] rules = [new ExecutableUploadExtensionRule(), new PhpContentInUploadRule()];
var engine = new InspectionEngine(rules);
var context = new InspectionContext(
    site.Id,
    "wordpress-one.example",
    "POST",
    "/wp-admin/async-upload.php",
    "example.php",
    "application/octet-stream",
    "<?php echo 'test';"u8.ToArray());

var result = await engine.InspectAsync(context, site);
Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));

internal sealed class AppConfiguration
{
    public SiteOptions[] Sites { get; init; } = [];
}

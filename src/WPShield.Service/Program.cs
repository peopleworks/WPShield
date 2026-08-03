using System.Text.Json;
using System.Text.Json.Serialization;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Rules.WordPress;

var configurationPath = args.FirstOrDefault();

if (string.IsNullOrWhiteSpace(configurationPath))
{
    configurationPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
}
else if (!Path.IsPathRooted(configurationPath))
{
    configurationPath = Path.GetFullPath(configurationPath);
}

if (!File.Exists(configurationPath))
{
    throw new FileNotFoundException(
        $"WPShield configuration file was not found: '{configurationPath}'.",
        configurationPath);
}

var json = await File.ReadAllTextAsync(configurationPath);
var serializerOptions = new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
};
serializerOptions.Converters.Add(new JsonStringEnumConverter());

var configuration = JsonSerializer.Deserialize<AppConfiguration>(json, serializerOptions)
    ?? throw new InvalidOperationException("Configuration is empty.");

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
var outputOptions = new JsonSerializerOptions { WriteIndented = true };
outputOptions.Converters.Add(new JsonStringEnumConverter());
Console.WriteLine(JsonSerializer.Serialize(result, outputOptions));

internal sealed class AppConfiguration
{
    public SiteOptions[] Sites { get; init; } = [];
}

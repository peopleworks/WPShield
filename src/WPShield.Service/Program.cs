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

IInspectionRule[] rules =
[
    new ExecutableUploadExtensionRule(),
    new DisguisedExtensionRule(),
    new IisExecutableUploadRule(),
    new IisConfigurationUploadRule(),
    new UnsafeFileNameRule(),
    new PhpContentInUploadRule()
];
var engine = new InspectionEngine(rules);

// A deliberately evasive but harmless synthetic name. Every trick here defeats a naive check that
// reads only the final extension: a directory prefix, an executable extension hidden behind an image
// extension, and a trailing dot that Windows strips on write.
var context = new InspectionContext(
    site.Id,
    "wordpress-one.example",
    "POST",
    "/wp-admin/async-upload.php",
    @"..\..\photo.php.jpg.",
    "image/jpeg",
    "<?php echo 'synthetic marker';"u8.ToArray());

var result = await engine.InspectAsync(context, site);
var outputOptions = new JsonSerializerOptions { WriteIndented = true };
outputOptions.Converters.Add(new JsonStringEnumConverter());
Console.WriteLine(JsonSerializer.Serialize(result, outputOptions));

internal sealed class AppConfiguration
{
    public SiteOptions[] Sites { get; init; } = [];
}

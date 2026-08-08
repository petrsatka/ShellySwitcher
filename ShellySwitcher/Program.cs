using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
using ShellySwitcher.Workers;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<PresenceOptions>(builder.Configuration.GetSection("Presence"));

builder.Services.AddSingleton<DeviceTracker>();
// arp-scan je Linux-only nástroj - na Windows (vývoj) se místo něj použije
// FileArpScanner čtoucí fixture soubor (Presence:DevArpScanFile).
if (OperatingSystem.IsLinux())
    builder.Services.AddSingleton<IArpScanner, ArpScanner>();
else
    builder.Services.AddSingleton<IArpScanner, FileArpScanner>();

builder.Services.AddHttpClient<IShellyClient, ShellyClient>();

builder.Services.AddSingleton<SocketStateStore>();
builder.Services.AddHostedService<ScanWorker>();
builder.Services.AddHostedService<EvaluationWorker>();

var host = builder.Build();
host.Run();
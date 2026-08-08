using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
using ShellySwitcher.Workers;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.Configure<PresenceOptions>(builder.Configuration.GetSection("Presence"));

builder.Services.AddSingleton<DeviceTracker>();
// arp-scan is a Linux-only tool - on Windows (development) FileArpScanner
// reading a fixture file (Presence:DevArpScanFile) is used instead.
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
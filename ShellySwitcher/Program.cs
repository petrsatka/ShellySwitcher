using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
using ShellySwitcher.Workers;

var builder = Host.CreateApplicationBuilder(args);

builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = true;
    options.SingleLine = true;
});

builder.Services.Configure<PresenceOptions>(builder.Configuration.GetSection("Presence"));

builder.Services.AddSingleton<DeviceTracker>();
builder.Services.AddSingleton<IArpScanner, ArpScanner>();
builder.Services.AddHttpClient<IShellyClient, ShellyClient>();
builder.Services.AddSingleton<SocketStateStore>();
builder.Services.AddHostedService<ScanWorker>();
builder.Services.AddHostedService<EvaluationWorker>();

var host = builder.Build();
host.Run();
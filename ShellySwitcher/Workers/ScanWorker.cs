using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
using ShellySwitcher.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace ShellySwitcher.Workers
{
    public class ScanWorker : BackgroundService
    {
        private readonly IOptionsMonitor<PresenceOptions> _options;
        private readonly IArpScanner _scanner;
        private readonly DeviceTracker _tracker;
        private readonly ILogger<ScanWorker> _logger;

        public ScanWorker(
            IOptionsMonitor<PresenceOptions> options,
            IArpScanner scanner,
            DeviceTracker tracker,
            ILogger<ScanWorker> logger)
        {
            _options = options;
            _scanner = scanner;
            _tracker = tracker;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var options = _options.CurrentValue;

                // Same range across multiple sockets is scanned only once.
                var addresses = options.Sockets
                    .Select(s => (Start: s.RangeStartAddress, End: s.RangeEndAddress))
                    .DistinctBy(r => (r.Start.ToString(), r.End.ToString()))
                    .SelectMany(r => IpRangeHelper.Enumerate(r.Start, r.End))
                    .DistinctBy(ip => ip.ToString()).ToList();

                try
                {
                    var results = await _scanner.ScanAsync(options.Interface, addresses, stoppingToken);

                    foreach (var result in results)
                    {
                        _tracker.SetStatus(result.Ip, result.Present);

                        if (result.Present)
                        {
                            _logger.LogInformation("Device {Ip} is present", result.Ip);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Scan failed");
                }

                await Task.Delay(TimeSpan.FromMinutes(options.ScanIntervalMinutes), stoppingToken);
            }
        }
    }
}

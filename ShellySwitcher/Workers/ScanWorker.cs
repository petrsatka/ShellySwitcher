using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
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

                // Stejný rozsah napříč víc zásuvkami scanujeme jen jednou.
                var ranges = options.Sockets
                    .Select(s => (Start: s.RangeStartAddress, End: s.RangeEndAddress))
                    .DistinctBy(r => (r.Start.ToString(), r.End.ToString()));

                foreach (var (start, end) in ranges)
                {
                    try
                    {
                        var devices = await _scanner.ScanAsync(options.Interface, start, end, stoppingToken);

                        foreach (var device in devices)
                            _tracker.MarkSeen(device.Ip);

                        _logger.LogInformation(
                            "Scan {Start}-{End}: nalezeno {Count} zařízení", start, end, devices.Count);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Scan rozsahu {Start}-{End} selhal", start, end);
                    }
                }

                await Task.Delay(TimeSpan.FromMinutes(options.ScanIntervalMinutes), stoppingToken);
            }
        }
    }
}

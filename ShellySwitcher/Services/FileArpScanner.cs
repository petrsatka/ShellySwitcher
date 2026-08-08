using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShellySwitcher.Models;
using ShellySwitcher.Options;
using ShellySwitcher.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ShellySwitcher.Services
{
    /// <summary>
    /// Náhrada ArpScanService pro vývoj mimo Linux (arp-scan tam není dostupný).
    /// Čte stejný textový formát ("ip\tmac\tvendor") ze souboru nakonfigurovaného
    /// v Presence:DevArpScanFile - stačí ho ručně přepisovat a simulovat tak
    /// příchod/odchod zařízení bez reálné sítě.
    ///
    /// Registruje se místo ArpScanService jen když OperatingSystem.IsLinux() == false,
    /// viz Program.cs.
    /// </summary>
    public class FileArpScanner : IArpScanner
    {
        private readonly IOptionsMonitor<PresenceOptions> _options;
        private readonly ILogger<FileArpScanner> _logger;

        public FileArpScanner(IOptionsMonitor<PresenceOptions> options, ILogger<FileArpScanner> logger)
        {
            _options = options;
            _logger = logger;
        }

        public async Task<IReadOnlyList<DiscoveredDevice>> ScanAsync(
            string interfaceName, IPAddress start, IPAddress end, CancellationToken ct)
        {
            var path = _options.CurrentValue.DevArpScanFile;

            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                _logger.LogWarning(
                    "DevArpScanFile '{Path}' neexistuje - scan vrátí prázdný výsledek.", path);
                return Array.Empty<DiscoveredDevice>();
            }

            var content = await File.ReadAllTextAsync(path, ct);
            var devices = ArpScanOutputParser.Parse(content)
                .Where(d => IpRangeHelper.IsInRange(d.Ip, start, end))
                .ToList();

            _logger.LogDebug(
                "FileArpScanner ({Path}) {Start}-{End}: {Count} zařízení", path, start, end, devices.Count);

            return devices;
        }
    }
}

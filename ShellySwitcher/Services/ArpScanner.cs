using Microsoft.Extensions.Logging;
using ShellySwitcher.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace ShellySwitcher.Services
{
    public interface IArpScanner
    {
        Task<IReadOnlyList<DiscoveredDevice>> ScanAsync(
            string interfaceName, IPAddress start, IPAddress end, CancellationToken ct);
    }

    /// <summary>
    /// Volá externí `arp-scan` nástroj a parsuje jeho výstup.
    /// Vyžaduje: sudo apt install arp-scan
    ///           sudo setcap cap_net_raw+ep /usr/sbin/arp-scan
    /// (setcap eliminuje potřebu spouštět službu jako root)
    /// </summary>
    public class ArpScanner : IArpScanner
    {
        private readonly ILogger<ArpScanner> _logger;

        public ArpScanner(ILogger<ArpScanner> logger)
        {
            _logger = logger;
        }

        public async Task<IReadOnlyList<DiscoveredDevice>> ScanAsync(
            string interfaceName, IPAddress start, IPAddress end, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "arp-scan",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("--quiet");
            psi.ArgumentList.Add("--interface");
            psi.ArgumentList.Add(interfaceName);
            psi.ArgumentList.Add($"{start}-{end}");

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Nepodařilo se spustit arp-scan.");

            string output = await process.StandardOutput.ReadToEndAsync(ct);
            string error = await process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            // arp-scan vrací nenulový exit code i za běžných okolností (viz jeho man page),
            // takže exit code sám o sobě nepovažujeme za chybu - jen zalogujeme stderr.
            if (!string.IsNullOrWhiteSpace(error))
                _logger.LogDebug("arp-scan stderr: {Error}", error);

            return ParseOutput(output);
        }

        private static List<DiscoveredDevice> ParseOutput(string output) =>
            ArpScanOutputParser.Parse(output);
    }
}

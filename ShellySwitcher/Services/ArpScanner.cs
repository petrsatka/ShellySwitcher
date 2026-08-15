using Microsoft.Extensions.Logging;
using ShellySwitcher.Models;
using ShellySwitcher.Utils;
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
        Task<IReadOnlyList<AddressStatus>> ScanAsync(
            string interfaceName, List<IPAddress> addresses, CancellationToken ct);
    }

    /// <summary>
    /// Presence detection via ping + kernel neighbor (ARP) cache.
    ///
    /// Why not arp-scan/arping: both are standalone tools without memory between
    /// individual process runs - the first packet to an unknown/unconfirmed
    /// address is always broadcast, which WiFi AP delivers to sleeping devices only on
    /// a sparse DTIM cycle (easily misses).
    ///
    /// The kernel, on the other hand, maintains ARP cache across the entire uptime. Once it
    /// knows the MAC address (STALE record), it performs revalidation itself via UNICAST probe
    /// (delivered more reliably, on every TIM, not just DTIM). Therefore: send
    /// ping (triggers revalidation), read state from `ip neigh show`.
    ///
    /// ICMP response itself does not immediately confirm NUD state to REACHABLE
    /// (kernel does not count it as "upper-layer confirmation") - right after ping you
    /// typically see DELAY or PROBE, not REACHABLE directly. All three states
    /// however mean "kernel knows the record and is revalidating it", not that it failed -
    /// so we treat them all as "present".
    ///
    /// Requires only ping (usually without capabilities) and `ip` (iproute2, part
    /// of basic installation). No additional setcap needed.
    /// </summary>
    public partial class ArpScanner : IArpScanner
    {
        private static readonly string[] PresentStates = ["REACHABLE", "DELAY", "PROBE"];

        private readonly ILogger<ArpScanner> _logger;

        public ArpScanner(ILogger<ArpScanner> logger)
        {
            _logger = logger;
        }

        public async Task<IReadOnlyList<AddressStatus>> ScanAsync(
            string interfaceName, List<IPAddress> addresses, CancellationToken ct)
        {
            // Ping all addresses at once - just triggers revalidation in kernel,
            // we don't care about the response itself (see comment above).
            _logger.LogInformation("Pinging {Count} addresses on interface {InterfaceName}", addresses.Count, interfaceName);
            await Task.WhenAll(addresses.Select(ip => PingAsync(interfaceName, ip, ct)));

            var neighState = await ReadNeighborTableAsync(interfaceName, ct);

            var results = new List<AddressStatus>();
            foreach (var ip in addresses)
            {
                bool present = neighState.TryGetValue(ip.ToString(), out var state) && PresentStates.Contains(state);
                results.Add(new AddressStatus(ip, present));
            }

            return results;
        }

        private static async Task PingAsync(string interfaceName, IPAddress ip, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ping",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("1");
            psi.ArgumentList.Add("-W"); psi.ArgumentList.Add("1");
            psi.ArgumentList.Add("-I"); psi.ArgumentList.Add(interfaceName);
            psi.ArgumentList.Add(ip.ToString());

            try
            {
                using var process = Process.Start(psi)!;
                await process.WaitForExitAsync(ct);
            }
            catch
            {
                // Ping result doesn't matter - even a "failed" ping triggers revalidation
                // in the neighbor table. An error running ping itself should not fail the scan.
            }
        }

        private async Task<Dictionary<string, string>> ReadNeighborTableAsync(
            string interfaceName, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ip",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("neigh");
            psi.ArgumentList.Add("show");
            psi.ArgumentList.Add("dev");
            psi.ArgumentList.Add(interfaceName);

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start 'ip neigh show'.");

            string output = await process.StandardOutput.ReadToEndAsync(ct);
            string error = await process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            if (!string.IsNullOrWhiteSpace(error))
                _logger.LogDebug("ip neigh stderr: {Error}", error);

            return ParseNeighborTable(output);
        }

        // Line: "192.168.1.105 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        // (for INCOMPLETE/FAILED without MAC record, the "lladdr ..." part is missing)
        [GeneratedRegex(@"^(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?(?<state>REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT)\s*$")]
        private static partial Regex NeighLineRegex();

        private static Dictionary<string, string> ParseNeighborTable(string output)
        {
            var result = new Dictionary<string, string>();

            foreach (var line in output.Split('\n'))
            {
                var match = NeighLineRegex().Match(line.Trim());
                if (match.Success)
                    result[match.Groups["ip"].Value] = match.Groups["state"].Value;
            }

            return result;
        }
    }
}

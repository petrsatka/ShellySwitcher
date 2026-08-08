using ShellySwitcher.Models;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace ShellySwitcher.Services
{
    /// <summary>
    /// Parses text output in arp-scan format ("<ip>\t<mac>\t<vendor>").
    /// Shared between ArpScanService (real scan) and FileArpScanner (debugging on Windows).
    /// </summary>
    public static partial class ArpScanOutputParser
    {
        [GeneratedRegex(@"^(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[0-9a-fA-F:]{17})")]
        private static partial Regex LineRegex();

        public static List<DiscoveredDevice> Parse(string output)
        {
            var results = new List<DiscoveredDevice>();

            foreach (var line in output.Split('\n'))
            {
                var match = LineRegex().Match(line);
                if (!match.Success)
                    continue;

                if (IPAddress.TryParse(match.Groups["ip"].Value, out var ip))
                    results.Add(new DiscoveredDevice(match.Groups["mac"].Value, ip));
            }

            return results;
        }
    }
}

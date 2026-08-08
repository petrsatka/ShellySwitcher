using ShellySwitcher.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ShellySwitcher.Services
{
    /// <summary>
    /// Drží mapu IP -> čas posledního výskytu v ARP scanu.
    /// Zapisuje ScanWorker, čte EvaluationWorker - proto ConcurrentDictionary.
    /// </summary>
    public class DeviceTracker
    {
        private readonly ConcurrentDictionary<string, DateTime> _lastSeenUtc = new();

        public void MarkSeen(IPAddress ip) => _lastSeenUtc[ip.ToString()] = DateTime.UtcNow;

        public DateTime? GetLastSeenUtc(IPAddress ip) =>
            _lastSeenUtc.TryGetValue(ip.ToString(), out var t) ? t : null;

        /// <summary>
        /// Bylo v daném IP rozsahu aspoň jedno zařízení viděné během posledních `within`?
        /// </summary>
        public bool AnyPresentInRange(IPAddress start, IPAddress end, TimeSpan within)
        {
            var cutoff = DateTime.UtcNow - within;

            foreach (var (ipText, lastSeen) in _lastSeenUtc)
            {
                if (lastSeen < cutoff)
                    continue;

                if (!IPAddress.TryParse(ipText, out var ip))
                    continue;

                if (IpRangeHelper.IsInRange(ip, start, end))
                    return true;
            }

            return false;
        }
    }
}

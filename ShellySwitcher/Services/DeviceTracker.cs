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
        private sealed class DeviceStatus
        {
            public bool Present;
            public DateTime LastOnlineUtc;
        }

        private readonly ConcurrentDictionary<string, DeviceStatus> _status = new();

        public void SetStatus(IPAddress ip, bool present)
        {
            var now = DateTime.UtcNow;
            _status.AddOrUpdate(ip.ToString(),
                _ => new DeviceStatus { Present = present, LastOnlineUtc = present ? now : DateTime.MinValue },
                (_, existing) =>
                {
                    existing.Present = present;
                    if (present)
                        existing.LastOnlineUtc = now;
                    return existing;
                });
        }

        public bool AnyPresentInRange(IPAddress start, IPAddress end, TimeSpan absenceTimeout)
        {
            var cutoff = DateTime.UtcNow - absenceTimeout;

            foreach (var (ipText, status) in _status)
            {
                if (!IPAddress.TryParse(ipText, out var ip))
                    continue;

                if (!IpRangeHelper.IsInRange(ip, start, end))
                    continue;

                // Last scan confirms it as present - no time comparison needed.
                if (status.Present)
                {
                    return true;
                }

                //Confirmed not found now, but last online was within tolerance.
                if (status.LastOnlineUtc >= cutoff)
                {
                    return true;
                }
            }

            return false;
        }
    }
}

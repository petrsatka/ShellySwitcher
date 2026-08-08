using System;
using System.Collections.Generic;
using System.Text;

namespace ShellySwitcher.Options
{
    public class PresenceOptions
    {
        public int ScanIntervalMinutes { get; set; } = 2;
        public string Interface { get; set; } = "eth0";
        public List<SocketConfig> Sockets { get; set; } = new();

        /// <summary>
        /// Path to the file with fixture data for FileArpScanner (debugging outside Linux).
        /// Not used on Linux - real arp-scan runs there.
        /// </summary>
        public string DevArpScanFile { get; set; } = "arp-scan-sample.txt";
    }
}

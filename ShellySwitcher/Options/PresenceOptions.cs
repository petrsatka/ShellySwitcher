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
        /// Cesta k souboru s fixture daty pro FileArpScanner (ladění mimo Linux).
        /// Na Linuxu se nepoužívá - tam běží reálný arp-scan.
        /// </summary>
        public string DevArpScanFile { get; set; } = "arp-scan-sample.txt";
    }
}

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json.Serialization;

namespace ShellySwitcher.Options
{
    public class TimeRange
    {
        public TimeOnly Start { get; set; }
        public TimeOnly End { get; set; }

        /// <summary>
        /// Podporuje i rozsahy přes půlnoc (např. 22:00-06:00).
        /// </summary>
        public bool Contains(TimeOnly now) =>
            Start <= End
                ? now >= Start && now < End
                : now >= Start || now < End;
    }
    public class SocketConfig
    {
        public string Name { get; set; } = "";
        public string Address { get; set; } = "";
        public string Username { get; set; } = "admin";
        public string Password { get; set; } = "";
        public string RangeStart { get; set; } = "";
        public string RangeEnd { get; set; } = "";
        public int AbsenceTimeoutMinutes { get; set; } = 15;
        public List<TimeRange> ForcedOffRanges { get; set; } = new();

        // Konfigurace nese IP jako string (kvůli JSON bindingu), tyto property
        // dávají zbytku kódu rovnou IPAddress bez opakovaného parsování.
        [JsonIgnore]
        public IPAddress RangeStartAddress => IPAddress.Parse(RangeStart);

        [JsonIgnore]
        public IPAddress RangeEndAddress => IPAddress.Parse(RangeEnd);
    }
}

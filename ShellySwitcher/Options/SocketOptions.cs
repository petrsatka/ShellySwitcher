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
        /// Supports ranges spanning midnight (e.g., 22:00-06:00).
        /// </summary>
        public bool Contains(TimeOnly now) =>
            Start <= End
                ? now >= Start && now < End
                : now >= Start || now < End;
    }

    public class SafetyCheckOptions
    {
        public bool Enabled { get; set; } = false;
        public double ThresholdWatts { get; set; } = 20;
        public int DelayMs { get; set; } = 1500;
    }

    public class SocketConfig
    {
        public string Name { get; set; } = "";
        public string Address { get; set; } = "";
        public string Username { get; set; } = "admin";
        public string Password { get; set; } = "";
        public string RangeStart { get; set; } = "";
        public string RangeEnd { get; set; } = "";
        public int AbsenceTimeoutMinutes { get; set; } = 5;
        public List<TimeRange> ForcedOffRanges { get; set; } = new();

        public SafetyCheckOptions SafetyCheck { get; set; } = new();

        // Configuration carries IP as string (due to JSON binding), these properties
        // provide the rest of the code with IPAddress directly without repeated parsing.
        [JsonIgnore]
        public IPAddress RangeStartAddress => IPAddress.Parse(RangeStart);

        [JsonIgnore]
        public IPAddress RangeEndAddress => IPAddress.Parse(RangeEnd);
    }
}

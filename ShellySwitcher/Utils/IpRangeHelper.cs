using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ShellySwitcher.Utils
{
    public static class IpRangeHelper
    {
        public static IEnumerable<IPAddress> Enumerate(IPAddress start, IPAddress end)
        {
            uint s = ToUInt32(start);
            uint e = ToUInt32(end);
            for (uint i = s; i <= e; i++)
                yield return FromUInt32(i);
        }

        public static bool IsInRange(IPAddress address, IPAddress start, IPAddress end)
        {
            uint addr = ToUInt32(address);
            uint s = ToUInt32(start);
            uint e = ToUInt32(end);
            return addr >= s && addr <= e;
        }

        private static IPAddress FromUInt32(uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return new IPAddress(bytes);
        }

        private static uint ToUInt32(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ShellySwitcher.Models
{
    public record DiscoveredDevice(string Mac, IPAddress Ip);
}

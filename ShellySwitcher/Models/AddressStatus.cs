using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ShellySwitcher.Models
{
    public record AddressStatus(IPAddress Ip, bool Present);
}

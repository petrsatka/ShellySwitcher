using Microsoft.Extensions.Logging;
using ShellySwitcher.Options;

namespace ShellySwitcher.Services
{
    public interface ISafetyCheckService
    {
        /// <summary>
        /// Checks power draw right after turning the socket on. If it's at or
        /// above the configured threshold - either immediately or after the
        /// configured delay - turns the socket back off.
        /// Does nothing if SafetyCheckEnabled is false. Stateless - call this
        /// once, right after a successful SetSwitchAsync(on: true).
        /// </summary>
        Task RunAsync(SocketConfig socket, CancellationToken ct);
    }

    public class SafetyCheckService : ISafetyCheckService
    {
        private readonly IShellyClient _shelly;
        private readonly ILogger<SafetyCheckService> _logger;

        public SafetyCheckService(IShellyClient shelly, ILogger<SafetyCheckService> logger)
        {
            _shelly = shelly;
            _logger = logger;
        }

        public async Task RunAsync(SocketConfig socket, CancellationToken ct)
        {
            if (!socket.SafetyCheck.Enabled)
                return;

            await Task.Delay(socket.SafetyCheck.DelayMs, ct);

            if (await ExceedsThresholdAsync(socket, ct))
                await TurnOffAsync(socket, $"{socket.SafetyCheck.DelayMs}ms after turn-on", ct);
        }

        private async Task<bool> ExceedsThresholdAsync(SocketConfig socket, CancellationToken ct)
        {
            var power = await _shelly.GetPowerAsync(socket, ct);

            if (power is null)
            {
                _logger.LogWarning(
                    "Shelly {Name} ({Address}): could not read power for safety check",
                    socket.Name, socket.Address);
                return false; // unknown reading - don't trip a false positive
            }

            return power >= socket.SafetyCheck.ThresholdWatts;
        }

        private async Task TurnOffAsync(SocketConfig socket, string when, CancellationToken ct)
        {
            _logger.LogWarning(
                "Shelly {Name} ({Address}): unattended draw detected {When} (threshold {Threshold}W) - switching back off",
                socket.Name, socket.Address, when, socket.SafetyCheck.ThresholdWatts);

            await _shelly.SetSwitchAsync(socket, false, ct);
        }
    }
}
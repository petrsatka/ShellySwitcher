using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShellySwitcher.Models;
using ShellySwitcher.Options;
using ShellySwitcher.Services;
using System.Collections.Concurrent;

namespace ShellySwitcher.Workers
{
    public class SocketStateStore
    {
        private readonly ConcurrentDictionary<string, DesiredState> _states = new();

        public DesiredState? Get(string socketName) =>
            _states.TryGetValue(socketName, out var s) ? s : null;

        public void Set(string socketName, DesiredState state) =>
            _states[socketName] = state;
    }

    public class EvaluationWorker : BackgroundService
    {
        private static readonly TimeSpan EvaluationInterval = TimeSpan.FromSeconds(30);

        private readonly IOptionsMonitor<PresenceOptions> _options;
        private readonly DeviceTracker _tracker;
        private readonly IShellyClient _shelly;
        private readonly SocketStateStore _stateStore;
        private readonly ILogger<EvaluationWorker> _logger;

        public EvaluationWorker(
            IOptionsMonitor<PresenceOptions> options,
            DeviceTracker tracker,
            IShellyClient shelly,
            SocketStateStore stateStore,
            ILogger<EvaluationWorker> logger)
        {
            _options = options;
            _tracker = tracker;
            _shelly = shelly;
            _stateStore = stateStore;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var options = _options.CurrentValue;
                var now = TimeOnly.FromDateTime(DateTime.Now);

                foreach (var socket in options.Sockets)
                {
                    try
                    {
                        // Vynucené vypnutí má vždy přednost před presence logikou.
                        bool forcedOff = socket.ForcedOffRanges.Any(r => r.Contains(now));

                        bool presenceDetected = _tracker.AnyPresentInRange(
                            socket.RangeStartAddress,
                            socket.RangeEndAddress,
                            TimeSpan.FromMinutes(socket.AbsenceTimeoutMinutes));

                        var desired = forcedOff ? DesiredState.OffBySchedule : (presenceDetected ? DesiredState.On : DesiredState.Off);
                        var previous = _stateStore.Get(socket.Name);

                        if (previous != desired)
                        {
                            bool physicalOn = desired == DesiredState.On;
                            await _shelly.SetSwitchAsync(socket, physicalOn, stoppingToken);
                            _stateStore.Set(socket.Name, desired);

                            _logger.LogInformation("{Name}: {Previous} -> {Desired}", socket.Name, previous, desired);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Vyhodnocení zásuvky {Name} selhalo", socket.Name);
                    }
                }

                await Task.Delay(EvaluationInterval, stoppingToken);
            }
        }
    }
}

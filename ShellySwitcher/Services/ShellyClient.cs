using Microsoft.Extensions.Logging;
using ShellySwitcher.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ShellySwitcher.Services
{
    public interface IShellyClient
    {
        Task<bool> SetSwitchAsync(SocketConfig socket, bool on, CancellationToken ct);
    }

    /// <summary>
    /// RPC client for Shelly Gen2/3 devices (Digest Auth, RFC 7616, SHA-256).
    ///
    /// Flow (up to 3 passes of the outer loop):
    ///   1. Send a request - authenticated if we already have a nonce, otherwise plain.
    ///   2. 200      -> done.
    ///   3. 401      -> store the new nonce from this response, send ONE authenticated
    ///                  request. 200 -> done. Anything else -> can't log in,
    ///                  clear the nonce, end the algorithm (no further retries).
    ///   4. 429      -> clear the nonce, wait 3s, go back to step 1 (new pass).
    ///
    /// A failure while parsing the challenge (unexpected device response) is logged
    /// and ends the algorithm right away - it's not a state that a retry would fix.
    ///
    /// All HTTP response disposal goes through "using var" as a safety net (runs
    /// automatically when the block is left, including via continue/return/exception).
    /// On 429, though, the request/response are disposed explicitly right away, so
    /// the TCP connection returns to the pool before the 3s wait starts - otherwise
    /// it would be held unnecessarily for the whole wait (the second Dispose() from
    /// "using" is a no-op, not an error).
    /// </summary>
    public partial class ShellyClient : IShellyClient
    {
        private const int MaxAttempts = 3;//429 from authenticated request + 429 from new unauthenticated request (429 from first authenticated request does not trigger nonce buffer eviction) + 401 from new unauthenticated request
        private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(3000); //2000 by documentation, but 3000 is for sure enough to avoid 429 on the next request

        private readonly HttpClient _http;
        private readonly ILogger<ShellyClient> _logger;
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
        private readonly ConcurrentDictionary<string, DigestState> _states = new();

        public ShellyClient(HttpClient http, ILogger<ShellyClient> logger)
        {
            _http = http;
            _logger = logger;
        }

        public Task<bool> SetSwitchAsync(SocketConfig socket, bool on, CancellationToken ct)
        {
            var uri = $"http://{socket.Address}/rpc/Switch.Set";
            var body = JsonSerializer.Serialize(new { id = 0, on });
            return SendWithAuthAsync(socket, HttpMethod.Post, uri, body, ct);
        }

        private async Task<bool> SendWithAuthAsync(
            SocketConfig socket, HttpMethod method, string uri, string body, CancellationToken ct)
        {
            var gate = _locks.GetOrAdd(socket.Address, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync(ct);

            try
            {
                var state = _states.GetOrAdd(socket.Address, _ => new DigestState());

                for (int attempt = 1; attempt <= MaxAttempts; attempt++)
                {
                    using var request = BuildRequest(method, uri, body, socket, state);
                    using var response = await _http.SendAsync(request, ct);

                    if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    {
                        _logger.LogDebug(
                            "Shelly {Name} ({Address}): 429 (attempt {Attempt}/{Max}), clearing nonce and waiting {Delay}",
                            socket.Name, socket.Address, attempt, MaxAttempts, RetryDelay);

                        state.Clear();

                        // Release the connection before waiting - no point holding it
                        // for RetryDelay when we're discarding response/request anyway.
                        response.Dispose();
                        request.Dispose();

                        await Task.Delay(RetryDelay, ct);
                        continue;
                    }

                    if (response.StatusCode != HttpStatusCode.Unauthorized)
                    {   //200 or other non-401/429 response - either success or a failure that won't be fixed by retrying.
                        return await FinishAsync(socket, response, ct);
                    }

                    try
                    {   // 401 - parse the challenge and send one authenticated request.
                        ParseChallenge(response, state);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex,
                            "Shelly {Name} ({Address}): failed to process Digest challenge - unexpected response",
                            socket.Name, socket.Address);
                        return false;
                    }

                    using var authedRequest = BuildAuthenticatedRequest(method, uri, body, socket, state);
                    using var authedResponse = await _http.SendAsync(authedRequest, ct);

                    if (!authedResponse.IsSuccessStatusCode)
                    {   // 401 after authentication or other failure - can't log in, clear the nonce and end the algorithm.
                        state.Clear();
                    }

                    return await FinishAsync(socket, authedResponse, ct);
                }

                _logger.LogWarning(
                    "Shelly {Name} ({Address}): attempts exhausted ({Max}), device still returning 429",
                    socket.Name, socket.Address, MaxAttempts);
                return false;
            }
            finally
            {
                gate.Release();
            }
        }

        private async Task<bool> FinishAsync(SocketConfig socket, HttpResponseMessage response, CancellationToken ct)
        {
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            var content = await response.Content.ReadAsStringAsync(ct);
            _logger.LogWarning(
                "Shelly {Name} ({Address}) Switch.Set failed: {Status} {Body}",
                socket.Name, socket.Address, response.StatusCode, content);
            return false;
        }

        private static HttpRequestMessage BuildRequest(
            HttpMethod method, string uri, string body, SocketConfig socket, DigestState state) =>
            state.HasChallenge
                ? BuildAuthenticatedRequest(method, uri, body, socket, state)
                : BuildPlainRequest(method, uri, body);

        private static HttpRequestMessage BuildPlainRequest(HttpMethod method, string uri, string body)
        {
            return new HttpRequestMessage(method, uri)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
        }

        private static HttpRequestMessage BuildAuthenticatedRequest(
            HttpMethod method, string uri, string body, SocketConfig socket, DigestState state)
        {
            var request = new HttpRequestMessage(method, uri)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };

            var path = new Uri(uri).PathAndQuery;
            var nc = state.NextNc();
            var response = ComputeResponse(
                socket.Username, socket.Password, state.Realm!, state.Nonce!, nc, state.CNonce!, method.Method, path);

            var header =
                $"username=\"{socket.Username}\", realm=\"{state.Realm}\", nonce=\"{state.Nonce}\", " +
                $"uri=\"{path}\", qop=auth, nc={nc}, cnonce=\"{state.CNonce}\", response=\"{response}\", algorithm=SHA-256";

            request.Headers.Authorization = new AuthenticationHeaderValue("Digest", header);
            return request;
        }

        private static void ParseChallenge(HttpResponseMessage response, DigestState state)
        {
            var digestHeader = response.Headers.WwwAuthenticate.FirstOrDefault(h => h.Scheme == "Digest")
                ?? throw new InvalidOperationException(
                    "Device responded with 401, but without a Digest challenge - unexpected response.");

            var parameters = ParseDigestParameters(digestHeader.Parameter ?? "");

            state.Realm = parameters["realm"];
            state.Nonce = parameters["nonce"];
            state.CNonce = Guid.NewGuid().ToString("N");
            state.ResetNc();
        }

        [GeneratedRegex("(\\w+)=\"?([^\",]+)\"?")]
        private static partial Regex DigestParamRegex();

        private static Dictionary<string, string> ParseDigestParameters(string raw)
        {
            var result = new Dictionary<string, string>();
            foreach (Match m in DigestParamRegex().Matches(raw))
                result[m.Groups[1].Value] = m.Groups[2].Value;
            return result;
        }

        private static string ComputeResponse(
            string username, string password, string realm, string nonce, string nc, string cnonce,
            string method, string uri)
        {
            var ha1 = Sha256Hex($"{username}:{realm}:{password}");
            var ha2 = Sha256Hex($"{method}:{uri}");
            return Sha256Hex($"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}");
        }

        private static string Sha256Hex(string input)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>Digest auth state for a single Shelly device - kept between requests (persistent login).</summary>
        private sealed class DigestState
        {
            public string? Realm;
            public string? Nonce;
            public string? CNonce;
            private int _nc;

            public bool HasChallenge => Nonce is not null;

            public void ResetNc() => _nc = 0;

            public string NextNc() => Interlocked.Increment(ref _nc).ToString("x8");

            public void Clear()
            {
                Realm = null;
                Nonce = null;
                CNonce = null;
                _nc = 0;
            }
        }
    }
}
using Microsoft.Extensions.Logging;
using ShellySwitcher.Options;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.Eventing.Reader;
using System.Linq.Expressions;
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
    /// Strategy: persistent login with fallback.
    ///  - If we already have a valid nonce for a given device, we send an authenticated
    ///    request directly (nc is incremented on each call).
    ///  - If we get 401 (first request, or nonce expired), we perform a handshake
    ///    (read WWW-Authenticate) and retry the request with a new nonce.
    /// </summary>
    public partial class ShellyClient : IShellyClient
    {
        private readonly HttpClient _http;
        private readonly ILogger<ShellyClient> _logger;
        private readonly ConcurrentDictionary<string, DigestState> _states = new();
        private const int MaxRetries = 3;
        private const int RetryDelayMs = 3000;

        public ShellyClient(HttpClient http, ILogger<ShellyClient> logger)
        {
            _http = http;
            _logger = logger;
        }

        public async Task<bool> SetSwitchAsync(SocketConfig socket, bool on, CancellationToken ct)
        {
            var uri = $"http://{socket.Address}/rpc/Switch.Set";
            var body = JsonSerializer.Serialize(new { id = 0, on });

            using var response = await SendWithAuthAsync(socket, HttpMethod.Post, uri, body, ct);

            if (!response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning(
                    "Shelly {Name} ({Address}) Switch.Set failed: {Status} {Body}",
                    socket.Name, socket.Address, response.StatusCode, content);
                return false;
            }
            return true;
        }

        private async Task<HttpResponseMessage> SendWithAuthAsync(
            SocketConfig socket, HttpMethod method, string uri, string body, CancellationToken ct)
        {
            var state = _states.GetOrAdd(socket.Address, _ => new DigestState());

            // Preemptive attempt with existing nonce, if we have it.
            if (state.HasChallenge)
            {
                HttpResponseMessage response;
                using (var request = BuildAuthenticatedRequest(method, uri, body, socket, state))
                {
                    response = await _http.SendAsync(request, ct);
                }

                var responseStatusCode = response.StatusCode;
                if (responseStatusCode != HttpStatusCode.Unauthorized && responseStatusCode != HttpStatusCode.TooManyRequests)
                {
                    return response;
                }

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    // A 401 response normally carries a fresh Digest challenge,
                    // so we can authenticate directly from this response without
                    // sending another unauthenticated request.
                    try
                    {
                        ParseChallenge(response, state);
                        using var retryRequest = BuildAuthenticatedRequest(method, uri, body, socket, state);
                        var retryResponse = await _http.SendAsync(retryRequest, ct);
                        response.Dispose();
                        return retryResponse;
                    }
                    catch (Exception ex) when (ex is InvalidOperationException || ex is KeyNotFoundException)
                    {
                        _logger.LogWarning("Shelly {Name} ({Address}) returned 401 with invalid WWW-Authenticate header.", socket.Name, socket.Address);
                        _logger.LogInformation("Continuing with handshake to get a new nonce.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error");
                        response.Dispose();
                        state.Clear();
                        throw;
                    }
                }

                // nonce expired / stale - discard and perform new handshake below.
                response.Dispose();
                state.Clear();

                if (responseStatusCode == HttpStatusCode.TooManyRequests)
                {   // Shelly may return 429 instead of 401 when the nonce is no longer
                    // available in the nonce store. This is inconsistent with the documented
                    // behavior for an unknown/stale nonce.
                    await Task.Delay(RetryDelayMs, ct); // wait before retrying
                }
            }

            // Handshake: plain request without auth -> read challenge -> retry with auth.
            for (int attempt = 0; attempt < MaxRetries; attempt++)
            {
                HttpResponseMessage challengeResponse;
                using (var challengeRequest = BuildPlainRequest(method, uri, body))
                {
                    challengeResponse = await _http.SendAsync(challengeRequest, ct);
                }

                if (challengeResponse.StatusCode != HttpStatusCode.Unauthorized && challengeResponse.StatusCode != HttpStatusCode.TooManyRequests)
                {
                    return challengeResponse; // authentication on device is not enabled
                }

                if (challengeResponse.StatusCode == HttpStatusCode.TooManyRequests)
                {//This is documented behavior. If there is no empty slot for the new nonce, the device returns 429. Client must wait a bit before retrying.
                    if (attempt + 1 < MaxRetries)
                    {
                        challengeResponse.Dispose();
                        await Task.Delay(RetryDelayMs, ct);
                        continue;
                    }
                    else
                    {
                        return challengeResponse;
                    }
                }

                try
                {
                    ParseChallenge(challengeResponse, state);
                }
                finally
                {
                    challengeResponse.Dispose();
                }

                break; // challenge parsed,
            }

            using var authedRequest = BuildAuthenticatedRequest(method, uri, body, socket, state);
            return await _http.SendAsync(authedRequest, ct);
        }

        private static HttpRequestMessage BuildPlainRequest(HttpMethod method, string uri, string body)
        {
            var request = new HttpRequestMessage(method, uri)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            return request;
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
                    "Device responded with 401, but without Digest challenge - unexpected response.");

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

        /// <summary>Digest auth state for a single Shelly device - maintained between requests (persistent login).</summary>
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

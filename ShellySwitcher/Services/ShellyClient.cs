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
        Task SetSwitchAsync(SocketConfig socket, bool on, CancellationToken ct);
    }

    /// <summary>
    /// RPC klient pro Shelly Gen2/3 zařízení (Digest Auth, RFC 7616, SHA-256).
    ///
    /// Strategie: trvalé přihlášení s fallbackem.
    ///  - Pokud pro dané zařízení už máme platný nonce, pošleme rovnou autentizovaný
    ///    request (nc se inkrementuje při každém volání).
    ///  - Pokud přijde 401 (první request, nebo nonce vypršel), provedeme handshake
    ///    (přečteme WWW-Authenticate) a zopakujeme request s novým nonce.
    /// </summary>
    public partial class ShellyClient : IShellyClient
    {
        private readonly HttpClient _http;
        private readonly ILogger<ShellyClient> _logger;
        private readonly ConcurrentDictionary<string, DigestState> _states = new();

        public ShellyClient(HttpClient http, ILogger<ShellyClient> logger)
        {
            _http = http;
            _logger = logger;
        }

        public async Task SetSwitchAsync(SocketConfig socket, bool on, CancellationToken ct)
        {
            var uri = $"http://{socket.Address}/rpc/Switch.Set";
            var body = JsonSerializer.Serialize(new { id = 0, on });

            using var response = await SendWithAuthAsync(socket, HttpMethod.Post, uri, body, ct);

            if (!response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(ct);
                _logger.LogWarning(
                    "Shelly {Name} ({Address}) Switch.Set selhal: {Status} {Body}",
                    socket.Name, socket.Address, response.StatusCode, content);
            }
        }

        private async Task<HttpResponseMessage> SendWithAuthAsync(
            SocketConfig socket, HttpMethod method, string uri, string body, CancellationToken ct)
        {
            var state = _states.GetOrAdd(socket.Address, _ => new DigestState());

            // Preemptivní pokus s existujícím nonce, pokud ho máme.
            if (state.HasChallenge)
            {
                var request = BuildAuthenticatedRequest(method, uri, body, socket, state);
                var response = await _http.SendAsync(request, ct);

                if (response.StatusCode != HttpStatusCode.Unauthorized)
                    return response;

                // nonce vypršel / stale - zahodíme a uděláme nový handshake níže.
                response.Dispose();
            }

            // Handshake: čistý request bez auth -> přečti challenge -> zopakuj s auth.
            using (var challengeRequest = BuildPlainRequest(method, uri, body))
            {
                var challengeResponse = await _http.SendAsync(challengeRequest, ct);

                if (challengeResponse.StatusCode != HttpStatusCode.Unauthorized)
                    return challengeResponse; // autentizace na zařízení není zapnutá

                ParseChallenge(challengeResponse, state);
                challengeResponse.Dispose();
            }

            var authedRequest = BuildAuthenticatedRequest(method, uri, body, socket, state);
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
                    "Zařízení odpovědělo 401, ale bez Digest challenge - neočekávaná odpověď.");

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

        /// <summary>Digest auth stav pro jedno Shelly zařízení - drží se mezi requesty (trvalé přihlášení).</summary>
        private sealed class DigestState
        {
            public string? Realm;
            public string? Nonce;
            public string? CNonce;
            private int _nc;

            public bool HasChallenge => Nonce is not null;

            public void ResetNc() => _nc = 0;

            public string NextNc() => Interlocked.Increment(ref _nc).ToString("x8");
        }
    }

}

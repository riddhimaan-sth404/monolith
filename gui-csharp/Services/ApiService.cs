using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MonolithGui.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace MonolithGui.Services
{
    public class ApiException : Exception
    {
        public int StatusCode { get; }
        public ApiException(string message, int statusCode)
            : base($"API error ({statusCode}): {message}")
        {
            StatusCode = statusCode;
        }
    }

    public class ApiService : IApiService
    {
        private readonly ISettingsService _settings;
        private readonly ILogger<ApiService> _logger;
        private HttpClient _httpClient;
        // Deserialize: camelCase/snake_case -> PascalCase properties via Newtonsoft default
        private static readonly JsonSerializerSettings _readSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };
        // Serialize: preserve field names exactly as written (anonymous objects use snake_case)
        private static readonly JsonSerializerSettings _writeSettings = new JsonSerializerSettings
        {
            ContractResolver = new Newtonsoft.Json.Serialization.DefaultContractResolver(),
            NullValueHandling = NullValueHandling.Ignore
        };

        public ApiService(ISettingsService settings, ILogger<ApiService> logger)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClient = CreateHttpClient();
        }

        public void ReconfigureHandler()
        {
            _logger.LogInformation("Reconfiguring HttpClient handler (BaseUrl: {Url})", _settings.BaseUrl);
            var old = _httpClient;
            _httpClient = CreateHttpClient();
            old.Dispose();
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();
            if (!_settings.ValidateTls)
            {
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }

            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            return client;
        }

        private void ApplyAuth(HttpRequestMessage request)
        {
            var token = _settings.LoadToken();
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        private string BuildUrl(string path)
        {
            if (path.StartsWith("http://") || path.StartsWith("https://")) return path;
            return $"{_settings.BaseUrl}{path}";
        }

        public async Task<T?> GetAsync<T>(string path)
        {
            var url = BuildUrl(path);
            _logger.LogDebug("GET request: {Url}", url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                ApplyAuth(request);

                using var response = await _httpClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    var error = TryDeserialize<ApiErrorResponse>(body);
                    throw new ApiException(error?.Message ?? error?.Error ?? response.ReasonPhrase ?? "Unknown GET error", (int)response.StatusCode);
                }

                if (typeof(T) == typeof(string)) return (T)(object)body;
                return JsonConvert.DeserializeObject<T>(body, _readSettings);
            }
            catch (Exception ex) when (!(ex is ApiException))
            {
                _logger.LogError(ex, "GET request failed for url {Url}", url);
                throw;
            }
        }

        public async Task<TResponse?> PostAsync<TRequest, TResponse>(string path, TRequest payload)
        {
            var url = BuildUrl(path);
            _logger.LogDebug("POST request: {Url}", url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, url);
                ApplyAuth(request);

                if (payload != null)
                {
                    var json = JsonConvert.SerializeObject(payload, _writeSettings);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }

                using var response = await _httpClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    var error = TryDeserialize<ApiErrorResponse>(body);
                    throw new ApiException(error?.Message ?? error?.Error ?? response.ReasonPhrase ?? "Unknown POST error", (int)response.StatusCode);
                }

                if (typeof(TResponse) == typeof(object) && string.IsNullOrWhiteSpace(body)) return default;
                if (typeof(TResponse) == typeof(string)) return (TResponse)(object)body;

                return JsonConvert.DeserializeObject<TResponse>(body, _readSettings);
            }
            catch (Exception ex) when (!(ex is ApiException))
            {
                _logger.LogError(ex, "POST request failed for url {Url}", url);
                throw;
            }
        }

        public async Task<TResponse?> PutAsync<TRequest, TResponse>(string path, TRequest payload)
        {
            var url = BuildUrl(path);
            _logger.LogDebug("PUT request: {Url}", url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Put, url);
                ApplyAuth(request);

                if (payload != null)
                {
                    var json = JsonConvert.SerializeObject(payload, _writeSettings);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }

                using var response = await _httpClient.SendAsync(request);
                var body = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    var error = TryDeserialize<ApiErrorResponse>(body);
                    throw new ApiException(error?.Message ?? error?.Error ?? response.ReasonPhrase ?? "Unknown PUT error", (int)response.StatusCode);
                }

                if (typeof(TResponse) == typeof(object) && string.IsNullOrWhiteSpace(body)) return default;
                if (typeof(TResponse) == typeof(string)) return (TResponse)(object)body;

                return JsonConvert.DeserializeObject<TResponse>(body, _readSettings);
            }
            catch (Exception ex) when (!(ex is ApiException))
            {
                _logger.LogError(ex, "PUT request failed for url {Url}", url);
                throw;
            }
        }

        public async Task<byte[]?> GetBytesAsync(string path)
        {
            var url = BuildUrl(path);
            _logger.LogDebug("GET bytes request: {Url}", url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                ApplyAuth(request);

                using var response = await _httpClient.SendAsync(request);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("GET bytes failed: {Status} for {Url}", response.StatusCode, url);
                    return null;
                }

                return await response.Content.ReadAsByteArrayAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GET bytes request failed for url {Url}", url);
                return null;
            }
        }

        public async Task<bool> DeleteAsync(string path)
        {
            var url = BuildUrl(path);
            _logger.LogDebug("DELETE request: {Url}", url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Delete, url);
                ApplyAuth(request);

                using var response = await _httpClient.SendAsync(request);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "DELETE request failed for url {Url}", url);
                return false;
            }
        }

        private static T? TryDeserialize<T>(string json) where T : class
        {
            try { return JsonConvert.DeserializeObject<T>(json, _readSettings); }
            catch { return null; }
        }
    }
}

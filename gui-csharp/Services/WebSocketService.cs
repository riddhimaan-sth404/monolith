using System;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace MonolithGui.Services
{
    public class WebSocketService : IWebSocketService
    {
        private readonly ISettingsService _settings;
        private readonly ILogger<WebSocketService> _logger;
        private CancellationTokenSource? _cts;
        private ClientWebSocket? _client;

        public event Action<string>? OnEventReceived;
        public event Action<bool>? OnConnectionStatusChanged;

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            private set
            {
                if (_isConnected != value)
                {
                    _isConnected = value;
                    OnConnectionStatusChanged?.Invoke(value);
                }
            }
        }

        public WebSocketService(ISettingsService settings, ILogger<WebSocketService> logger)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task StartAsync()
        {
            await StopAsync();
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => ConnectionLoop(_cts.Token));
        }

        public async Task StopAsync()
        {
            if (_cts != null)
            {
                _cts.Cancel();
                _cts.Dispose();
                _cts = null;
            }

            if (_client != null)
            {
                try
                {
                    if (_client.State == WebSocketState.Open)
                    {
                        await _client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client stopping", CancellationToken.None);
                    }
                }
                catch { }
                _client.Dispose();
                _client = null;
            }

            IsConnected = false;
        }

        private async Task ConnectionLoop(CancellationToken ct)
        {
            int consecutiveFailures = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (_client != null)
                    {
                        try { _client.Dispose(); } catch { }
                    }
                    _client = new ClientWebSocket();
                    var token = _settings.LoadToken();
                    if (!string.IsNullOrEmpty(token))
                    {
                        _client.Options.SetRequestHeader("Authorization", $"Bearer {token}");
                    }

                    var wsUrl = $"wss://{_settings.Host}:{_settings.Port}/api/v1/ws/events";
                    _logger.LogInformation("Connecting to WebSocket event bus: {Url}", wsUrl);

                    if (!_settings.ValidateTls)
                    {
                        var expectedHost = _settings.Host;
                        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                        {
                            if (sender is HttpWebRequest req && req.RequestUri != null)
                            {
                                if (req.RequestUri.Host.Equals(expectedHost, StringComparison.OrdinalIgnoreCase))
                                    return true;
                            }
                            if (sender is string host && host.Equals(expectedHost, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                            // Fallback check on the certificate subject/DNS name
                            if (cert != null && cert.Subject.Contains(expectedHost))
                            {
                                return true;
                            }
                            return sslPolicyErrors == System.Net.Security.SslPolicyErrors.None;
                        };
                    }

                    await _client.ConnectAsync(new Uri(wsUrl), ct);
                    IsConnected = true;
                    consecutiveFailures = 0;
                    _logger.LogInformation("WebSocket connected.");

                    var buffer = new byte[65536];
                    while (_client.State == WebSocketState.Open && !ct.IsCancellationRequested)
                    {
                        var result = await _client.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                        if (result.MessageType == WebSocketMessageType.Text)
                        {
                            var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                            OnEventReceived?.Invoke(message);
                        }
                        else if (result.MessageType == WebSocketMessageType.Close)
                        {
                            break;
                        }
                    }
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    _logger.LogWarning("WebSocket loop exception: {Message}", ex.Message);
                    consecutiveFailures++;
                }
                finally
                {
                    IsConnected = false;
                    if (_client != null)
                    {
                        try { _client.Dispose(); } catch { }
                        _client = null;
                    }
                }

                if (!ct.IsCancellationRequested)
                {
                    // Exponential backoff capped at 60 seconds (5s, 10s, 20s, 40s, 60s...)
                    int delayMs = Math.Min(60000, 5000 * (int)Math.Pow(2, Math.Min(4, consecutiveFailures)));
                    await Task.Delay(delayMs, ct).ContinueWith(_ => { });
                }
            }
        }
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;

namespace MonolithGui.Services
{
    public class SettingsModel
    {
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 8443;
        public bool ValidateTls { get; set; } = false;
        public bool GamingMode { get; set; } = false;
        public bool ContextMenu { get; set; } = true;
        public bool BatterySaver { get; set; } = false;
        public bool CodebertEnabled { get; set; } = true;
    }

    public class SettingsService : ISettingsService
    {
        private readonly string _settingsPath;
        private readonly string _tokenPath;
        private readonly ILogger<SettingsService> _logger;
        private SettingsModel _model;

        public string Host
        {
            get => _model.Host;
            set => _model.Host = value;
        }

        public int Port
        {
            get => _model.Port;
            set => _model.Port = value;
        }

        public bool ValidateTls
        {
            get => _model.ValidateTls;
            set => _model.ValidateTls = value;
        }

        public bool GamingMode
        {
            get => _model.GamingMode;
            set => _model.GamingMode = value;
        }

        public bool ContextMenu
        {
            get => _model.ContextMenu;
            set => _model.ContextMenu = value;
        }

        public bool BatterySaver
        {
            get => _model.BatterySaver;
            set => _model.BatterySaver = value;
        }

        public bool CodebertEnabled
        {
            get => _model.CodebertEnabled;
            set => _model.CodebertEnabled = value;
        }

        public string BaseUrl => $"https://{Host}:{Port}/api/v1";

        public SettingsService(ILogger<SettingsService> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dir = Path.Combine(appData, "Monolith");
            Directory.CreateDirectory(dir);

            _settingsPath = Path.Combine(dir, "appsettings.json");

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var tokenDir = Path.Combine(userProfile, ".config", "monolith");
            Directory.CreateDirectory(tokenDir);
            _tokenPath = Path.Combine(tokenDir, "token");

            _model = LoadSettings();
        }

        private SettingsModel LoadSettings()
        {
            if (File.Exists(_settingsPath))
            {
                try
                {
                    var json = File.ReadAllText(_settingsPath);
                    var loaded = JsonConvert.DeserializeObject<SettingsModel>(json);
                    if (loaded != null) return loaded;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load settings file. Falling back to defaults.");
                }
            }
            return new SettingsModel();
        }

        public void Save()
        {
            try
            {
                var json = JsonConvert.SerializeObject(_model, Formatting.Indented);
                File.WriteAllText(_settingsPath, json);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save settings file.");
            }
        }

        public string? LoadToken()
        {
            if (!File.Exists(_tokenPath)) return null;

            try
            {
                var encryptedBytes = File.ReadAllBytes(_tokenPath);
                if (encryptedBytes.Length == 0) return null;

                var decryptedBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(decryptedBytes).Trim();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt token using DPAPI. Trying plaintext fallback.");
                try
                {
                    var text = File.ReadAllText(_tokenPath).Trim();
                    if (!string.IsNullOrEmpty(text) && !text.Contains(" "))
                    {
                        SaveToken(text);
                        return text;
                    }
                }
                catch (Exception fallbackEx)
                {
                    _logger.LogError(fallbackEx, "Plaintext token fallback reading failed.");
                }
                return null;
            }
        }

        public void SaveToken(string token)
        {
            try
            {
                var rawBytes = Encoding.UTF8.GetBytes(token);
                var encryptedBytes = ProtectedData.Protect(rawBytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(_tokenPath, encryptedBytes);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to protect and save auth token.");
            }
        }

        public void ClearToken()
        {
            try
            {
                if (File.Exists(_tokenPath)) File.Delete(_tokenPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete/clear token file.");
            }
        }
    }
}

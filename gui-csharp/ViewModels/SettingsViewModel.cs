using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using MonolithGui.Models;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class SettingsViewModel : ViewModelBase
    {
        private readonly ISettingsService _settings;
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<SettingsViewModel> _logger;

        private string _settingsHost = "127.0.0.1";
        public string SettingsHost
        {
            get => _settingsHost;
            set => SetProperty(ref _settingsHost, value);
        }

        private string _settingsPort = "8443";
        public string SettingsPort
        {
            get => _settingsPort;
            set => SetProperty(ref _settingsPort, value);
        }

        private bool _validateTls;
        public bool ValidateTls
        {
            get => _validateTls;
            set => SetProperty(ref _validateTls, value);
        }

        private bool _gamingMode;
        public bool GamingMode
        {
            get => _gamingMode;
            set => SetProperty(ref _gamingMode, value);
        }

        private bool _contextMenu;
        public bool ContextMenu
        {
            get => _contextMenu;
            set => SetProperty(ref _contextMenu, value);
        }

        private bool _batterySaver;
        public bool BatterySaver
        {
            get => _batterySaver;
            set => SetProperty(ref _batterySaver, value);
        }

        private bool _codebertEnabled;
        public bool CodebertEnabled
        {
            get => _codebertEnabled;
            set => SetProperty(ref _codebertEnabled, value);
        }

        private string _mfaSecret = string.Empty;
        public string MfaSecret
        {
            get => _mfaSecret;
            set
            {
                if (SetProperty(ref _mfaSecret, value))
                {
                    OnPropertyChanged(nameof(HasMfaSecret));
                }
            }
        }

        public bool HasMfaSecret => !string.IsNullOrEmpty(MfaSecret);

        private string _mfaConfirmCode = string.Empty;
        public string MfaConfirmCode
        {
            get => _mfaConfirmCode;
            set => SetProperty(ref _mfaConfirmCode, value);
        }

        private LicenseStatus _license = new LicenseStatus();
        public LicenseStatus License
        {
            get => _license;
            set => SetProperty(ref _license, value);
        }

        private string _licenseKeyInput = string.Empty;
        public string LicenseKeyInput
        {
            get => _licenseKeyInput;
            set => SetProperty(ref _licenseKeyInput, value);
        }

        private string _diagLogs = string.Empty;
        public string DiagLogs
        {
            get => _diagLogs;
            set => SetProperty(ref _diagLogs, value);
        }

        private string _metricsOutput = string.Empty;
        public string MetricsOutput
        {
            get => _metricsOutput;
            set => SetProperty(ref _metricsOutput, value);
        }

        public ICommand SaveSettingsCommand { get; }
        public ICommand EnrollMfaCommand { get; }
        public ICommand ConfirmMfaCommand { get; }
        public ICommand DisableMfaCommand { get; }
        public ICommand UploadLicenseCommand { get; }
        public ICommand RefreshDiagLogsCommand { get; }
        public ICommand RefreshMetricsCommand { get; }

        public SettingsViewModel(
            ISettingsService settings,
            IApiService api,
            IDialogService dialog,
            ILogger<SettingsViewModel> logger)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            SaveSettingsCommand = new RelayCommand(async () => await SaveSettings());
            EnrollMfaCommand = new RelayCommand(async () => await EnrollMfa());
            ConfirmMfaCommand = new RelayCommand(async () => await ConfirmMfa());
            DisableMfaCommand = new RelayCommand(async () => await DisableMfa());
            UploadLicenseCommand = new RelayCommand(async () => await UploadLicense());
            RefreshDiagLogsCommand = new RelayCommand(async () => await LoadLogs());
            RefreshMetricsCommand = new RelayCommand(async () => await FetchMetrics());

            LoadSettingsValues();
        }

        public void LoadSettingsValues()
        {
            SettingsHost = _settings.Host;
            SettingsPort = _settings.Port.ToString();
            ValidateTls = _settings.ValidateTls;
            GamingMode = _settings.GamingMode;
            ContextMenu = _settings.ContextMenu;
            BatterySaver = _settings.BatterySaver;
            CodebertEnabled = _settings.CodebertEnabled;
            _ = LoadLogs();
            _ = LoadLicenseStatus();
        }

        private async Task SaveSettings()
        {
            _settings.Host = SettingsHost.Trim();
            if (int.TryParse(SettingsPort, out var p)) _settings.Port = p;
            _settings.ValidateTls = ValidateTls;
            _settings.GamingMode = GamingMode;
            _settings.ContextMenu = ContextMenu;
            _settings.BatterySaver = BatterySaver;
            _settings.CodebertEnabled = CodebertEnabled;
            _settings.Save();

            _api.ReconfigureHandler();
            await _dialog.ShowMessageAsync("Settings saved successfully.", "Settings Updated");
        }

        private async Task EnrollMfa()
        {
            try
            {
                var result = await _api.PostAsync<object, MfaEnrollResult>("/users/mfa/enroll", new { });
                if (result != null)
                {
                    MfaSecret = result.Secret;
                    await _dialog.ShowMessageAsync($"MFA Secret Key generated:\n{result.Secret}\n\nEnter code below to confirm.", "MFA Enrollment");
                }
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"MFA enrollment failed: {ex.Message}", "Error", true);
            }
        }

        private async Task ConfirmMfa()
        {
            if (string.IsNullOrWhiteSpace(MfaConfirmCode)) return;
            try
            {
                var payload = new { mfa_code = MfaConfirmCode.Trim() };
                await _api.PostAsync<object, object>("/users/mfa/confirm", payload);
                await _dialog.ShowMessageAsync("MFA multi-factor authentication successfully enabled!", "MFA Enabled");
                MfaConfirmCode = string.Empty;
                MfaSecret = string.Empty;
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"MFA confirmation failed: {ex.Message}", "Error", true);
            }
        }

        private async Task DisableMfa()
        {
            if (!await _dialog.ShowConfirmationAsync("Are you sure you want to disable Multi-Factor Authentication?", "Confirm Disable MFA")) return;

            try
            {
                await _api.PostAsync<object, object>("/users/mfa/disable", new { });
                await _dialog.ShowMessageAsync("MFA multi-factor authentication disabled.", "MFA Disabled");
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to disable MFA: {ex.Message}", "Error", true);
            }
        }

        private async Task LoadLicenseStatus()
        {
            try
            {
                var status = await _api.GetAsync<LicenseStatus>("/license/status") ?? new LicenseStatus();
                License = status;
            }
            catch { }
        }

        private async Task UploadLicense()
        {
            if (string.IsNullOrWhiteSpace(LicenseKeyInput)) return;
            try
            {
                var payload = new { license_key = LicenseKeyInput.Trim() };
                await _api.PostAsync<object, object>("/license/upload", payload);
                await _dialog.ShowMessageAsync("License key successfully uploaded and activated.", "License Activated");
                LicenseKeyInput = string.Empty;
                await LoadLicenseStatus();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"License activation failed: {ex.Message}", "Error", true);
            }
        }

        private async Task LoadLogs()
        {
            try
            {
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EDR", "logs", "gui.log");
                if (File.Exists(logPath))
                {
                    DiagLogs = await Task.Run(() => File.ReadAllText(logPath));
                }
                else
                {
                    DiagLogs = "No local diagnostic log file found.";
                }
            }
            catch (Exception ex)
            {
                DiagLogs = $"Error reading log file: {ex.Message}";
            }
        }

        public async Task FetchMetrics()
        {
            try
            {
                var rawMetrics = await _api.GetAsync<string>("/metrics");
                MetricsOutput = rawMetrics ?? "No metrics data returned.";
            }
            catch (Exception ex)
            {
                MetricsOutput = $"Failed to fetch metrics: {ex.Message}";
            }
        }
    }
}

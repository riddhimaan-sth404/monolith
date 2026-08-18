using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class LoginViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly ISettingsService _settings;
        private readonly IDialogService _dialog;
        private readonly ILogger<LoginViewModel> _logger;

        private string _username = "admin";
        public string Username
        {
            get => _username;
            set => SetProperty(ref _username, value);
        }

        private string _password = "admin";
        public string Password
        {
            get => _password;
            set => SetProperty(ref _password, value);
        }

        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            set => SetProperty(ref _isBusy, value);
        }

        private string _errorMessage = string.Empty;
        public string ErrorMessage
        {
            get => _errorMessage;
            set => SetProperty(ref _errorMessage, value);
        }

        public ICommand LoginCommand { get; }
        public event Action? OnLoginSuccess;

        public LoginViewModel(
            IApiService api,
            ISettingsService settings,
            IDialogService dialog,
            ILogger<LoginViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            LoginCommand = new RelayCommand(async () => await PerformLogin());
        }

        private async Task PerformLogin()
        {
            if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
            {
                ErrorMessage = "Please enter both username and password.";
                return;
            }

            IsBusy = true;
            ErrorMessage = string.Empty;

            try
            {
                var payload = new Dictionary<string, string>
                {
                    { "username", Username.Trim() },
                    { "password", Password }
                };

                var response = await _api.PostAsync<Dictionary<string, string>, Dictionary<string, object>>("/login", payload);
                if (response == null)
                {
                    ErrorMessage = "Invalid server response.";
                    return;
                }

                // Check for MFA required challenge
                if (response.TryGetValue("mfa_required", out var mfaReq) && mfaReq is bool req && req)
                {
                    var mfaCode = await _dialog.ShowMfaPromptAsync();
                    if (string.IsNullOrWhiteSpace(mfaCode))
                    {
                        ErrorMessage = "MFA code is required to complete authentication.";
                        return;
                    }

                    var mfaPayload = new Dictionary<string, string>
                    {
                        { "username", Username.Trim() },
                        { "mfa_code", mfaCode.Trim() }
                    };

                    var mfaResponse = await _api.PostAsync<Dictionary<string, string>, Dictionary<string, object>>("/login/mfa", mfaPayload);
                    if (mfaResponse != null && mfaResponse.TryGetValue("token", out var mfaToken) && mfaToken is string tokenStr)
                    {
                        _settings.SaveToken(tokenStr);
                        OnLoginSuccess?.Invoke();
                        return;
                    }
                    else
                    {
                        ErrorMessage = "MFA verification failed.";
                        return;
                    }
                }

                if (response.TryGetValue("token", out var token) && token is string t)
                {
                    _settings.SaveToken(t);
                    OnLoginSuccess?.Invoke();
                }
                else
                {
                    ErrorMessage = "Authentication failed.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed for user {User}", Username);
                ErrorMessage = ex.Message;
            }
            finally
            {
                IsBusy = false;
            }
        }
    }
}

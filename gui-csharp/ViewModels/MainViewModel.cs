using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly ISettingsService _settings;
        private readonly IWebSocketService _ws;
        private readonly ILogger<MainViewModel> _logger;

        public DashboardViewModel DashboardVM { get; }
        public EndpointsViewModel EndpointsVM { get; }
        public AlertsViewModel AlertsVM { get; }
        public ScanViewModel ScanVM { get; }
        public IocAllowlistViewModel IocAllowlistVM { get; }
        public PoliciesViewModel PoliciesVM { get; }
        public QuarantineViewModel QuarantineViewModel { get; }
        public ReportsViewModel ReportsVM { get; }
        public ToolsViewModel ToolsVM { get; }
        public SettingsViewModel SettingsVM { get; }

        private object _currentViewModel;
        public object CurrentViewModel
        {
            get => _currentViewModel;
            set => SetProperty(ref _currentViewModel, value);
        }

        private int _selectedNavIndex;
        public int SelectedNavIndex
        {
            get => _selectedNavIndex;
            set
            {
                if (SetProperty(ref _selectedNavIndex, value))
                {
                    _ = NavigateTo(value);
                    OnPropertyChanged(nameof(SelectedPanelTitle));
                }
            }
        }

        public string SelectedPanelTitle => _selectedNavIndex switch
        {
            0 => "Executive Dashboard",
            1 => "Endpoints & Host Control",
            2 => "Alerts & Threat Intelligence",
            3 => "System File & RAM Scanner",
            4 => "IoC Indicators & Exclusions",
            5 => "Security Policies",
            6 => "Quarantine Vault",
            7 => "Security Reports & Audit Trail",
            8 => "Administrative Tools",
            9 => "System Settings & MFA",
            _ => "Dashboard"
        };

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            set
            {
                if (SetProperty(ref _isConnected, value))
                {
                    OnPropertyChanged(nameof(ConnectionStatusText));
                    OnPropertyChanged(nameof(ConnectionStatusColor));
                }
            }
        }

        public string ConnectionStatusText => IsConnected ? "Connected" : "Disconnected";
        public string ConnectionStatusColor => IsConnected ? "#A6E3A1" : "#F38BA8";

        public ICommand NavigateCommand { get; }
        public ICommand LogoutCommand { get; }

        public event Action? OnLogout;

        public MainViewModel(
            IApiService api,
            ISettingsService settings,
            IWebSocketService ws,
            ILogger<MainViewModel> logger,
            DashboardViewModel dashboardVM,
            EndpointsViewModel endpointsVM,
            AlertsViewModel alertsVM,
            ScanViewModel scanVM,
            IocAllowlistViewModel iocAllowlistVM,
            PoliciesViewModel policiesVM,
            QuarantineViewModel quarantineViewModel,
            ReportsViewModel reportsVM,
            ToolsViewModel toolsVM,
            SettingsViewModel settingsVM)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _ws = ws ?? throw new ArgumentNullException(nameof(ws));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            DashboardVM = dashboardVM;
            EndpointsVM = endpointsVM;
            AlertsVM = alertsVM;
            ScanVM = scanVM;
            IocAllowlistVM = iocAllowlistVM;
            PoliciesVM = policiesVM;
            QuarantineViewModel = quarantineViewModel;
            ReportsVM = reportsVM;
            ToolsVM = toolsVM;
            SettingsVM = settingsVM;

            _currentViewModel = DashboardVM;

            NavigateCommand = new RelayCommand<string>(async (idxStr) =>
            {
                if (int.TryParse(idxStr, out var idx))
                {
                    await NavigateTo(idx);
                }
            });

            LogoutCommand = new RelayCommand(async () => await PerformLogout());

            _ws.OnConnectionStatusChanged += status => IsConnected = status;
        }

        public async Task InitializeAsync()
        {
            _logger.LogInformation("Initializing MainViewModel background tasks...");
            try
            {
                await DashboardVM.LoadDashboardData();
                IsConnected = true;
            }
            catch
            {
                IsConnected = false;
            }
            await _ws.StartAsync();
        }

        public void Cleanup()
        {
            _ws.OnConnectionStatusChanged -= status => IsConnected = status;
        }

        private async Task NavigateTo(int index)
        {
            SelectedNavIndex = index;
            CurrentViewModel = index switch
            {
                0 => DashboardVM,
                1 => EndpointsVM,
                2 => AlertsVM,
                3 => ScanVM,
                4 => IocAllowlistVM,
                5 => PoliciesVM,
                6 => QuarantineViewModel,
                7 => ReportsVM,
                8 => ToolsVM,
                9 => SettingsVM,
                _ => DashboardVM
            };

            switch (index)
            {
                case 0: await DashboardVM.LoadDashboardData(); break;
                case 1: await EndpointsVM.RefreshEndpoints(); break;
                case 2: await AlertsVM.RefreshAlerts(); break;
                case 3: await ScanVM.LoadHistory(); break;
                case 4: await IocAllowlistVM.RefreshData(); break;
                case 5: await PoliciesVM.RefreshData(); break;
                case 6: await QuarantineViewModel.RefreshQuarantine(); break;
                case 7: await ReportsVM.RefreshData(); break;
                case 8: await ToolsVM.RefreshAllowlist(); break;
                case 9: SettingsVM.LoadSettingsValues(); await SettingsVM.FetchMetrics(); break;
            }
        }

        private async Task PerformLogout()
        {
            await _ws.StopAsync();
            try
            {
                await _api.PostAsync<object, object>("/logout", new { });
            }
            catch { }
            _settings.ClearToken();
            OnLogout?.Invoke();
        }
    }
}

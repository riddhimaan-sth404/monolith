using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using MonolithGui.Models;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class AlertsViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<AlertsViewModel> _logger;

        public ObservableCollection<AlertItem> SecurityAlerts { get; } = new ObservableCollection<AlertItem>();
        public ObservableCollection<MemoryAlertItem> MemoryAlerts { get; } = new ObservableCollection<MemoryAlertItem>();
        public ObservableCollection<RegistryTamperAlertItem> RegistryTamperAlerts { get; } = new ObservableCollection<RegistryTamperAlertItem>();

        private List<AlertItem> _allSecurityAlerts = new List<AlertItem>();
        private List<MemoryAlertItem> _allMemoryAlerts = new List<MemoryAlertItem>();
        private List<RegistryTamperAlertItem> _allRegistryAlerts = new List<RegistryTamperAlertItem>();

        private AlertItem? _selectedAlert;
        public AlertItem? SelectedAlert
        {
            get => _selectedAlert;
            set
            {
                if (SetProperty(ref _selectedAlert, value))
                {
                    OnPropertyChanged(nameof(IsAlertSelected));
                }
            }
        }

        public bool IsAlertSelected => _selectedAlert != null;

        private MemoryAlertItem? _selectedMemoryAlert;
        public MemoryAlertItem? SelectedMemoryAlert
        {
            get => _selectedMemoryAlert;
            set
            {
                if (SetProperty(ref _selectedMemoryAlert, value))
                {
                    OnPropertyChanged(nameof(IsMemoryAlertSelected));
                }
            }
        }

        public bool IsMemoryAlertSelected => _selectedMemoryAlert != null;

        private RegistryTamperAlertItem? _selectedRegistryAlert;
        public RegistryTamperAlertItem? SelectedRegistryAlert
        {
            get => _selectedRegistryAlert;
            set
            {
                if (SetProperty(ref _selectedRegistryAlert, value))
                {
                    OnPropertyChanged(nameof(IsRegistryAlertSelected));
                }
            }
        }

        public bool IsRegistryAlertSelected => _selectedRegistryAlert != null;

        private string _searchText = string.Empty;
        public string SearchText
        {
            get => _searchText;
            set
            {
                if (SetProperty(ref _searchText, value))
                {
                    ApplyFilter();
                }
            }
        }

        private string _severityFilter = "All";
        public string SeverityFilter
        {
            get => _severityFilter;
            set
            {
                if (SetProperty(ref _severityFilter, value))
                {
                    ApplyFilter();
                }
            }
        }

        public ICommand RefreshCommand { get; }
        public ICommand SuppressAlertCommand { get; }
        public ICommand UnsuppressAlertCommand { get; }

        public AlertsViewModel(IApiService api, IDialogService dialog, ILogger<AlertsViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshAlerts());
            SuppressAlertCommand = new RelayCommand(async () => await SuppressSelected());
            UnsuppressAlertCommand = new RelayCommand(async () => await UnsuppressSelected());
        }

        public async Task RefreshAlerts()
        {
            IsLoading = true;
            try
            {
                var security = new List<AlertItem>();
                var alertsRes = await _api.GetAsync<Dictionary<string, object>>("/alerts");
                if (alertsRes != null && alertsRes.TryGetValue("alerts", out var alertsObj) && alertsObj != null)
                {
                    var list = Newtonsoft.Json.JsonConvert.DeserializeObject<List<AlertItem>>(alertsObj.ToString());
                    if (list != null) security = list;
                }

                var memory = await _api.GetAsync<List<MemoryAlertItem>>("/alerts/memory") ?? new List<MemoryAlertItem>();
                var registry = await _api.GetAsync<List<RegistryTamperAlertItem>>("/alerts/registry-tamper") ?? new List<RegistryTamperAlertItem>();

                _allSecurityAlerts = security;
                _allMemoryAlerts = memory;
                _allRegistryAlerts = registry;

                ApplyFilter();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load alerts data.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void ApplyFilter()
        {
            SecurityAlerts.Clear();
            MemoryAlerts.Clear();
            RegistryTamperAlerts.Clear();

            var query = SearchText.Trim().ToLowerInvariant();

            var filteredSecurity = _allSecurityAlerts.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(SeverityFilter) && SeverityFilter != "All")
            {
                filteredSecurity = filteredSecurity.Where(x => x.Severity.Equals(SeverityFilter, StringComparison.OrdinalIgnoreCase));
            }
            if (!string.IsNullOrWhiteSpace(query))
            {
                filteredSecurity = filteredSecurity.Where(x =>
                    (x.Title ?? "").ToLowerInvariant().Contains(query) ||
                    (x.Description ?? "").ToLowerInvariant().Contains(query) ||
                    (x.RuleId ?? "").ToLowerInvariant().Contains(query));
            }
            foreach (var s in filteredSecurity) SecurityAlerts.Add(s);

            var filteredMem = _allMemoryAlerts.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(query))
            {
                filteredMem = filteredMem.Where(x =>
                    (x.ProcessName ?? "").ToLowerInvariant().Contains(query) ||
                    (x.YaraMatches ?? "").ToLowerInvariant().Contains(query) ||
                    (x.Verdict ?? "").ToLowerInvariant().Contains(query));
            }
            foreach (var m in filteredMem) MemoryAlerts.Add(m);

            var filteredReg = _allRegistryAlerts.AsEnumerable();
            if (!string.IsNullOrWhiteSpace(query))
            {
                filteredReg = filteredReg.Where(x =>
                    (x.KeyPath ?? "").ToLowerInvariant().Contains(query) ||
                    (x.OffendingProcess ?? "").ToLowerInvariant().Contains(query) ||
                    (x.Operation ?? "").ToLowerInvariant().Contains(query));
            }
            foreach (var r in filteredReg) RegistryTamperAlerts.Add(r);
        }

        private async Task SuppressSelected()
        {
            if (SelectedAlert == null) return;
            try
            {
                await _api.PostAsync<object, object>($"/alerts/{SelectedAlert.Id}/suppress", new { });
                await RefreshAlerts();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to suppress alert: {ex.Message}", "Error", true);
            }
        }

        private async Task UnsuppressSelected()
        {
            if (SelectedAlert == null) return;
            try
            {
                await _api.PostAsync<object, object>($"/alerts/{SelectedAlert.Id}/unsuppress", new { });
                await RefreshAlerts();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to unsuppress alert: {ex.Message}", "Error", true);
            }
        }
    }
}

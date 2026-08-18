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
    public class PoliciesViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<PoliciesViewModel> _logger;

        public ObservableCollection<PolicyItem> Policies { get; } = new ObservableCollection<PolicyItem>();
        public ObservableCollection<EndpointItem> Endpoints { get; } = new ObservableCollection<EndpointItem>();

        private PolicyItem? _selectedPolicy;
        public PolicyItem? SelectedPolicy
        {
            get => _selectedPolicy;
            set => SetProperty(ref _selectedPolicy, value);
        }

        private EndpointItem? _selectedEndpoint;
        public EndpointItem? SelectedEndpoint
        {
            get => _selectedEndpoint;
            set => SetProperty(ref _selectedEndpoint, value);
        }

        private string _newPolicyName = string.Empty;
        public string NewPolicyName
        {
            get => _newPolicyName;
            set => SetProperty(ref _newPolicyName, value);
        }

        private int _scanInterval = 24;
        public int ScanInterval
        {
            get => _scanInterval;
            set => SetProperty(ref _scanInterval, value);
        }

        private bool _memoryScanEnabled = true;
        public bool MemoryScanEnabled
        {
            get => _memoryScanEnabled;
            set => SetProperty(ref _memoryScanEnabled, value);
        }

        private string _tamperLevel = "high";
        public string TamperLevel
        {
            get => _tamperLevel;
            set => SetProperty(ref _tamperLevel, value);
        }

        public ICommand RefreshCommand { get; }
        public ICommand CreatePolicyCommand { get; }
        public ICommand DeletePolicyCommand { get; }
        public ICommand AssignPolicyCommand { get; }

        public PoliciesViewModel(IApiService api, IDialogService dialog, ILogger<PoliciesViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshData());
            CreatePolicyCommand = new RelayCommand(async () => await CreatePolicy());
            DeletePolicyCommand = new RelayCommand<PolicyItem>(async item => await DeletePolicy(item));
            AssignPolicyCommand = new RelayCommand(async () => await AssignPolicy());
        }

        public async Task RefreshData()
        {
            IsLoading = true;
            try
            {
                var pols = new List<PolicyItem>();
                var polRes = await _api.GetAsync<Dictionary<string, object>>("/policies");
                if (polRes != null && polRes.TryGetValue("policies", out var policiesObj) && policiesObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<PolicyItem>>(policiesObj.ToString());
                    if (parsed != null) pols = parsed;
                }

                var eps = new List<EndpointItem>();
                var epRes = await _api.GetAsync<Dictionary<string, object>>("/endpoints");
                if (epRes != null && epRes.TryGetValue("endpoints", out var epsObj) && epsObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<EndpointItem>>(epsObj.ToString());
                    if (parsed != null) eps = parsed;
                }

                Policies.Clear();
                foreach (var p in pols) Policies.Add(p);

                Endpoints.Clear();
                foreach (var e in eps) Endpoints.Add(e);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load security policies.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private async Task CreatePolicy()
        {
            if (string.IsNullOrWhiteSpace(NewPolicyName)) return;
            try
            {
                var payload = new
                {
                    name = NewPolicyName.Trim(),
                    description = "Custom Policy Settings",
                    rules = new object[] { },
                    settings = new
                    {
                        quick_scan_interval_hours = ScanInterval,
                        memory_scan_enabled = MemoryScanEnabled,
                        tamper_protection_level = TamperLevel
                    }
                };

                await _api.PostAsync<object, object>("/policies", payload);
                NewPolicyName = string.Empty;
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to create policy: {ex.Message}", "Error", true);
            }
        }

        private async Task DeletePolicy(PolicyItem? policy)
        {
            if (policy == null) return;
            if (!await _dialog.ShowConfirmationAsync($"Delete security policy '{policy.Name}'?", "Confirm Delete")) return;

            try
            {
                await _api.DeleteAsync($"/policies/{policy.Id}");
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to delete policy: {ex.Message}", "Error", true);
            }
        }

        private async Task AssignPolicy()
        {
            if (SelectedPolicy == null || SelectedEndpoint == null)
            {
                await _dialog.ShowMessageAsync("Please select both a policy and an endpoint to assign.", "Selection Required");
                return;
            }

            try
            {
                var payload = new { endpoint_id = SelectedEndpoint.Id };
                await _api.PostAsync<object, object>($"/policies/{SelectedPolicy.Id}/assign", payload);
                await _dialog.ShowMessageAsync($"Successfully assigned policy '{SelectedPolicy.Name}' to '{SelectedEndpoint.Hostname}'.", "Policy Assigned");
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to assign policy: {ex.Message}", "Error", true);
            }
        }
    }
}

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
    public class EndpointsViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<EndpointsViewModel> _logger;

        public ObservableCollection<EndpointItem> Endpoints { get; } = new ObservableCollection<EndpointItem>();
        public ObservableCollection<string> HostEvents { get; } = new ObservableCollection<string>();

        private List<EndpointItem> _allEndpoints = new List<EndpointItem>();

        private EndpointItem? _selectedEndpoint;
        public EndpointItem? SelectedEndpoint
        {
            get => _selectedEndpoint;
            set
            {
                if (SetProperty(ref _selectedEndpoint, value))
                {
                    OnPropertyChanged(nameof(IsEndpointSelected));
                    _ = LoadHostEvents();
                }
            }
        }

        public bool IsEndpointSelected => _selectedEndpoint != null;

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

        private string _statusFilter = "All";
        public string StatusFilter
        {
            get => _statusFilter;
            set
            {
                if (SetProperty(ref _statusFilter, value))
                {
                    ApplyFilter();
                }
            }
        }

        public ICommand RefreshCommand { get; }
        public ICommand IsolateCommand { get; }
        public ICommand ReleaseCommand { get; }
        public ICommand ShredFileCommand { get; }

        public EndpointsViewModel(IApiService api, IDialogService dialog, ILogger<EndpointsViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshEndpoints());
            IsolateCommand = new RelayCommand(async () => await IsolateSelected());
            ReleaseCommand = new RelayCommand(async () => await ReleaseSelected());
            ShredFileCommand = new RelayCommand(async () => await ShredRemoteFile());
        }

        public async Task RefreshEndpoints()
        {
            IsLoading = true;
            try
            {
                var list = new List<EndpointItem>();
                var res = await _api.GetAsync<Dictionary<string, object>>("/endpoints");
                if (res != null && res.TryGetValue("endpoints", out var epsObj) && epsObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<EndpointItem>>(epsObj.ToString());
                    if (parsed != null) list = parsed;
                }
                _allEndpoints = list;
                ApplyFilter();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to fetch endpoints list.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void ApplyFilter()
        {
            Endpoints.Clear();
            var filtered = _allEndpoints.AsEnumerable();

            if (!string.IsNullOrWhiteSpace(StatusFilter) && StatusFilter != "All")
            {
                filtered = filtered.Where(x => x.Status.Equals(StatusFilter, StringComparison.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(SearchText))
            {
                var query = SearchText.Trim().ToLowerInvariant();
                filtered = filtered.Where(x =>
                    (x.Hostname != null && x.Hostname.ToLowerInvariant().Contains(query)) ||
                    (x.IpAddress != null && x.IpAddress.ToLowerInvariant().Contains(query)) ||
                    (x.OsVersion != null && x.OsVersion.ToLowerInvariant().Contains(query)));
            }

            foreach (var ep in filtered)
            {
                Endpoints.Add(ep);
            }
        }

        private async Task LoadHostEvents()
        {
            HostEvents.Clear();
            if (SelectedEndpoint == null) return;

            try
            {
                var events = new List<string>();
                var res = await _api.GetAsync<Dictionary<string, object>>($"/endpoints/{SelectedEndpoint.Id}/events");
                if (res != null && res.TryGetValue("events", out var evsObj) && evsObj != null)
                {
                    var serialized = Newtonsoft.Json.JsonConvert.SerializeObject(evsObj);
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<object>>(serialized);
                    if (parsed != null)
                    {
                        foreach (var ev in parsed)
                            events.Add(Newtonsoft.Json.JsonConvert.SerializeObject(ev, Newtonsoft.Json.Formatting.Indented));
                    }
                }
                foreach (var ev in events) HostEvents.Add(ev);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load host events for endpoint {Id}", SelectedEndpoint.Id);
            }
        }

        private async Task IsolateSelected()
        {
            if (SelectedEndpoint == null) return;
            var host = SelectedEndpoint;

            if (!await _dialog.ShowConfirmationAsync($"Are you sure you want to ISOLATE endpoint '{host.Hostname}' ({host.IpAddress}) from the network?\nOnly EDR management traffic will be allowed.", "Confirm Network Isolation")) return;

            try
            {
                await _api.PostAsync<object, object>($"/endpoints/{host.Id}/isolate", new { });
                await _dialog.ShowMessageAsync($"Endpoint '{host.Hostname}' successfully isolated.", "Isolation Initiated");
                await RefreshEndpoints();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Isolation failed: {ex.Message}", "Error", true);
            }
        }

        private async Task ReleaseSelected()
        {
            if (SelectedEndpoint == null) return;
            var host = SelectedEndpoint;

            if (!await _dialog.ShowConfirmationAsync($"Release endpoint '{host.Hostname}' back to the normal network?", "Confirm Host Release")) return;

            try
            {
                await _api.PostAsync<object, object>($"/endpoints/{host.Id}/release", new { });
                await _dialog.ShowMessageAsync($"Endpoint '{host.Hostname}' network isolation released.", "Host Released");
                await RefreshEndpoints();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Release failed: {ex.Message}", "Error", true);
            }
        }

        private async Task ShredRemoteFile()
        {
            if (SelectedEndpoint == null) return;
            var filePath = await _dialog.ShowInputDialogAsync("Enter absolute target file path to securely shred on remote endpoint:", "Remote File Shredding");
            if (string.IsNullOrWhiteSpace(filePath)) return;

            if (!await _dialog.ShowConfirmationAsync($"PERMANENTLY SHRED '{filePath}' on endpoint '{SelectedEndpoint.Hostname}'?", "Confirm Shredding")) return;

            try
            {
                var payload = new { file_path = filePath.Trim() };
                await _api.PostAsync<object, object>($"/endpoints/{SelectedEndpoint.Id}/shred", payload);
                await _dialog.ShowMessageAsync($"Remote file shredding command dispatched for '{filePath}'.", "Command Dispatched");
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Shredding command failed: {ex.Message}", "Error", true);
            }
        }
    }
}

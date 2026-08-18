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
    public class IocAllowlistViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<IocAllowlistViewModel> _logger;

        public ObservableCollection<IocItem> Iocs { get; } = new ObservableCollection<IocItem>();
        public ObservableCollection<AllowlistItem> AllowlistItems { get; } = new ObservableCollection<AllowlistItem>();

        private List<IocItem> _allIocs = new List<IocItem>();
        private List<AllowlistItem> _allAllowlist = new List<AllowlistItem>();

        private string _searchText = string.Empty;
        public string SearchText
        {
            get => _searchText;
            set
            {
                if (SetProperty(ref _searchText, value))
                {
                    ApplyFilters();
                }
            }
        }

        private string _newIocValue = string.Empty;
        public string NewIocValue
        {
            get => _newIocValue;
            set => SetProperty(ref _newIocValue, value);
        }

        private string _selectedIocType = "hash";
        public string SelectedIocType
        {
            get => _selectedIocType;
            set => SetProperty(ref _selectedIocType, value);
        }

        private string _newIocDesc = string.Empty;
        public string NewIocDesc
        {
            get => _newIocDesc;
            set => SetProperty(ref _newIocDesc, value);
        }

        private string _newAllowlistTarget = string.Empty;
        public string NewAllowlistTarget
        {
            get => _newAllowlistTarget;
            set => SetProperty(ref _newAllowlistTarget, value);
        }

        private string _selectedAllowlistType = "path";
        public string SelectedAllowlistType
        {
            get => _selectedAllowlistType;
            set => SetProperty(ref _selectedAllowlistType, value);
        }

        public ICommand RefreshCommand { get; }
        public ICommand AddIocCommand { get; }
        public ICommand DeleteIocCommand { get; }
        public ICommand AddAllowlistCommand { get; }
        public ICommand DeleteAllowlistCommand { get; }

        public IocAllowlistViewModel(IApiService api, IDialogService dialog, ILogger<IocAllowlistViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshData());
            AddIocCommand = new RelayCommand(async () => await AddIoc());
            DeleteIocCommand = new RelayCommand<IocItem>(async item => await DeleteIoc(item));
            AddAllowlistCommand = new RelayCommand(async () => await AddAllowlist());
            DeleteAllowlistCommand = new RelayCommand<AllowlistItem>(async item => await DeleteAllowlist(item));
        }

        public async Task RefreshData()
        {
            IsLoading = true;
            try
            {
                var iocs = new List<IocItem>();
                var iocRes = await _api.GetAsync<Dictionary<string, object>>("/iocs");
                if (iocRes != null && iocRes.TryGetValue("iocs", out var iocsObj) && iocsObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<IocItem>>(iocsObj.ToString());
                    if (parsed != null) iocs = parsed;
                }

                var allow = new List<AllowlistItem>();
                var allowRes = await _api.GetAsync<Dictionary<string, object>>("/allowlist");
                if (allowRes != null && allowRes.TryGetValue("rules", out var rulesObj) && rulesObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<AllowlistItem>>(rulesObj.ToString());
                    if (parsed != null) allow = parsed;
                }

                _allIocs = iocs;
                _allAllowlist = allow;

                ApplyFilters();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh IoCs and Allowlist.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void ApplyFilters()
        {
            Iocs.Clear();
            AllowlistItems.Clear();

            var query = SearchText.Trim().ToLowerInvariant();

            foreach (var i in _allIocs.Where(x => string.IsNullOrEmpty(query) || (x.Value ?? "").ToLowerInvariant().Contains(query) || (x.Description ?? "").ToLowerInvariant().Contains(query)))
            {
                Iocs.Add(i);
            }

            foreach (var a in _allAllowlist.Where(x => string.IsNullOrEmpty(query) || (x.Target ?? "").ToLowerInvariant().Contains(query)))
            {
                AllowlistItems.Add(a);
            }
        }

        private async Task AddIoc()
        {
            if (string.IsNullOrWhiteSpace(NewIocValue)) return;
            try
            {
                var payload = new { value = NewIocValue.Trim(), ioc_type = SelectedIocType, description = NewIocDesc.Trim() };
                await _api.PostAsync<object, object>("/iocs", payload);
                NewIocValue = string.Empty;
                NewIocDesc = string.Empty;
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to add IoC: {ex.Message}", "Error", true);
            }
        }

        private async Task DeleteIoc(IocItem? item)
        {
            if (item == null) return;
            if (!await _dialog.ShowConfirmationAsync($"Delete IoC rule '{item.Value}'?", "Confirm Delete")) return;
            try
            {
                await _api.DeleteAsync($"/iocs/{item.Id}");
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to delete IoC: {ex.Message}", "Error", true);
            }
        }

        private async Task AddAllowlist()
        {
            if (string.IsNullOrWhiteSpace(NewAllowlistTarget)) return;
            try
            {
                var payload = new { value = NewAllowlistTarget.Trim(), rule_type = SelectedAllowlistType };
                await _api.PostAsync<object, object>("/allowlist", payload);
                NewAllowlistTarget = string.Empty;
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to add Allowlist rule: {ex.Message}", "Error", true);
            }
        }

        private async Task DeleteAllowlist(AllowlistItem? item)
        {
            if (item == null) return;
            if (!await _dialog.ShowConfirmationAsync($"Remove '{item.Target}' from allowlist?", "Confirm Removal")) return;
            try
            {
                await _api.DeleteAsync($"/allowlist/{item.Id}");
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to remove allowlist item: {ex.Message}", "Error", true);
            }
        }
    }
}

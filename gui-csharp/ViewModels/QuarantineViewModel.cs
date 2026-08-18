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
    public class QuarantineViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<QuarantineViewModel> _logger;

        public ObservableCollection<QuarantineItem> QuarantineItems { get; } = new ObservableCollection<QuarantineItem>();

        private List<QuarantineItem> _allQuarantineItems = new List<QuarantineItem>();

        private QuarantineItem? _selectedQuarantineItem;
        public QuarantineItem? SelectedQuarantineItem
        {
            get => _selectedQuarantineItem;
            set
            {
                if (SetProperty(ref _selectedQuarantineItem, value))
                {
                    OnPropertyChanged(nameof(IsItemSelected));
                }
            }
        }

        public bool IsItemSelected => _selectedQuarantineItem != null;

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

        public ICommand RefreshCommand { get; }
        public ICommand RestoreQuarantineCommand { get; }
        public ICommand DeleteQuarantineCommand { get; }

        public QuarantineViewModel(IApiService api, IDialogService dialog, ILogger<QuarantineViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshQuarantine());
            RestoreQuarantineCommand = new RelayCommand(async () => await RestoreSelected());
            DeleteQuarantineCommand = new RelayCommand(async () => await DeleteSelected());
        }

        public async Task RefreshQuarantine()
        {
            IsLoading = true;
            try
            {
                var list = await _api.GetAsync<List<QuarantineItem>>("/scans/quarantine") ?? new List<QuarantineItem>();
                _allQuarantineItems = list;
                ApplyFilter();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load quarantine items.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void ApplyFilter()
        {
            QuarantineItems.Clear();
            var query = SearchText.Trim().ToLowerInvariant();

            foreach (var q in _allQuarantineItems.Where(x => string.IsNullOrEmpty(query) || (x.OriginalPath ?? "").ToLowerInvariant().Contains(query) || (x.Verdict ?? "").ToLowerInvariant().Contains(query)))
            {
                QuarantineItems.Add(q);
            }
        }

        private async Task RestoreSelected()
        {
            if (SelectedQuarantineItem == null) return;
            var item = SelectedQuarantineItem;

            if (!await _dialog.ShowConfirmationAsync($"Are you sure you want to restore '{item.OriginalPath}' to its original location?", "Confirm Restore")) return;

            try
            {
                await _api.PostAsync<object, object>($"/scans/{item.Id}/restore", new { });
                await _dialog.ShowMessageAsync("File successfully restored.", "Restore Complete");
                await RefreshQuarantine();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to restore file: {ex.Message}", "Error", true);
            }
        }

        private async Task DeleteSelected()
        {
            if (SelectedQuarantineItem == null) return;
            var item = SelectedQuarantineItem;

            if (!await _dialog.ShowConfirmationAsync($"PERMANENTLY DELETE '{item.OriginalPath}' from disk?", "Confirm Delete")) return;

            try
            {
                await _api.DeleteAsync($"/scans/{item.Id}");
                await _dialog.ShowMessageAsync("File permanently deleted.", "Deletion Complete");
                await RefreshQuarantine();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to delete file: {ex.Message}", "Error", true);
            }
        }
    }
}

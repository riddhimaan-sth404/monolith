using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using MonolithGui.Models;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class ToolsViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<ToolsViewModel> _logger;

        public ObservableCollection<AllowlistItem> AllowlistItems { get; } = new ObservableCollection<AllowlistItem>();

        private string _allowlistInput = string.Empty;
        public string AllowlistInput
        {
            get => _allowlistInput;
            set => SetProperty(ref _allowlistInput, value);
        }

        public ICommand GenerateReportCommand { get; }
        public ICommand AddAllowlistCommand { get; }

        public ToolsViewModel(IApiService api, IDialogService dialog, ILogger<ToolsViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            GenerateReportCommand = new RelayCommand(async () => await GenerateReport());
            AddAllowlistCommand = new RelayCommand(async () => await AddAllowlist());
        }

        private async Task GenerateReport()
        {
            try
            {
                var payload = new { report_type = "threat_summary" };
                var json = await _api.PostAsync<object, string>("/reports", payload);
                if (string.IsNullOrEmpty(json))
                {
                    await _dialog.ShowMessageAsync("Report generation returned empty data.", "Warning", true);
                    return;
                }

                var pdfBytes = await Task.Run(() => PdfReportGenerator.GenerateReportPdf("threat_summary", json));
                var dialog = new SaveFileDialog
                {
                    Title = "Save PDF Report",
                    Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*",
                    FileName = $"ExecutiveSummary_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
                };
                if (dialog.ShowDialog() == true)
                {
                    await Task.Run(() => File.WriteAllBytes(dialog.FileName, pdfBytes));
                    await _dialog.ShowMessageAsync($"PDF report saved:\n{dialog.FileName}", "Report Saved");
                }
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to generate report: {ex.Message}", "Error", true);
            }
        }

        private async Task AddAllowlist()
        {
            if (string.IsNullOrWhiteSpace(AllowlistInput)) return;
            try
            {
                var payload = new { value = AllowlistInput.Trim(), rule_type = "hash" };
                await _api.PostAsync<object, object>("/allowlist", payload);
                AllowlistInput = string.Empty;
                await RefreshAllowlist();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to add exclusion: {ex.Message}", "Error", true);
            }
        }

        public async Task RefreshAllowlist()
        {
            try
            {
                var allow = new List<AllowlistItem>();
                var res = await _api.GetAsync<Dictionary<string, object>>("/allowlist");
                if (res != null && res.TryGetValue("rules", out var rulesObj) && rulesObj != null)
                {
                    var parsed = Newtonsoft.Json.JsonConvert.DeserializeObject<List<AllowlistItem>>(rulesObj.ToString());
                    if (parsed != null) allow = parsed;
                }

                AllowlistItems.Clear();
                foreach (var a in allow) AllowlistItems.Add(a);
            }
            catch { }
        }
    }
}

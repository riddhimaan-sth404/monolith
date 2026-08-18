using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using MonolithGui.Models;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class ReportsViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<ReportsViewModel> _logger;

        public ObservableCollection<ReportItem> Reports { get; } = new ObservableCollection<ReportItem>();
        public ObservableCollection<AuditLogEntry> AuditLogs { get; } = new ObservableCollection<AuditLogEntry>();

        private ReportItem? _selectedReport;
        public ReportItem? SelectedReport
        {
            get => _selectedReport;
            set => SetProperty(ref _selectedReport, value);
        }

        private string _selectedReportType = "threat_summary";
        public string SelectedReportType
        {
            get => _selectedReportType;
            set => SetProperty(ref _selectedReportType, value);
        }

        public List<ReportTypeOption> ReportTypes { get; } = new List<ReportTypeOption>
        {
            new ReportTypeOption { Value = "threat_summary", DisplayName = "Threat Summary" },
            new ReportTypeOption { Value = "endpoint_health", DisplayName = "Endpoint Health" },
            new ReportTypeOption { Value = "ioc_inventory", DisplayName = "IoC Inventory" },
        };

        public ICommand RefreshCommand { get; }
        public ICommand GenerateReportCommand { get; }
        public ICommand DownloadReportCommand { get; }

        public ReportsViewModel(IApiService api, IDialogService dialog, ILogger<ReportsViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await RefreshData());
            GenerateReportCommand = new RelayCommand(async () => await GenerateReport());
            DownloadReportCommand = new RelayCommand<ReportItem>(async item => await DownloadReport(item));
        }

        public async Task RefreshData()
        {
            IsLoading = true;
            try
            {
                var repsRes = await _api.GetAsync<Dictionary<string, object>>("/reports");
                if (repsRes != null && repsRes.TryGetValue("reports", out var repsObj))
                {
                    var json = Newtonsoft.Json.JsonConvert.SerializeObject(repsObj);
                    var reps = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ReportItem>>(json);
                    if (reps != null)
                    {
                        Reports.Clear();
                        foreach (var r in reps) Reports.Add(r);
                    }
                }

                var audit = await _api.GetAsync<List<AuditLogEntry>>("/reports/audit-logs") ?? new List<AuditLogEntry>();
                AuditLogs.Clear();
                foreach (var a in audit) AuditLogs.Add(a);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load reports and audit logs.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private async Task GenerateReport()
        {
            try
            {
                var payload = new { report_type = SelectedReportType };
                var json = await _api.PostAsync<object, string>("/reports", payload);
                if (string.IsNullOrEmpty(json))
                {
                    await _dialog.ShowMessageAsync("Report generation returned empty data.", "Warning", true);
                    return;
                }

                var pdfBytes = await Task.Run(() => PdfReportGenerator.GenerateReportPdf(SelectedReportType, json));
                var dialog = new SaveFileDialog
                {
                    Title = "Save PDF Report",
                    Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*",
                    FileName = $"{SelectedReportType}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
                };
                if (dialog.ShowDialog() == true)
                {
                    await Task.Run(() => File.WriteAllBytes(dialog.FileName, pdfBytes));
                    await _dialog.ShowMessageAsync($"PDF report saved:\n{dialog.FileName}", "Report Saved");
                }
                await RefreshData();
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to generate report: {ex.Message}", "Error", true);
            }
        }

        private async Task DownloadReport(ReportItem? item)
        {
            if (item == null) return;
            try
            {
                var bytes = await _api.GetBytesAsync($"/reports/{item.Id}/download");
                if (bytes == null || bytes.Length == 0)
                {
                    await _dialog.ShowMessageAsync("Report content is empty.", "Warning", true);
                    return;
                }

                var json = Encoding.UTF8.GetString(bytes);
                var pdfBytes = await Task.Run(() => PdfReportGenerator.GenerateScanResultPdf(json));
                var dialog = new SaveFileDialog
                {
                    Title = "Save Scan Report as PDF",
                    Filter = "PDF files (*.pdf)|*.pdf|All files (*.*)|*.*",
                    FileName = $"ScanReport_{item.Id}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
                };
                if (dialog.ShowDialog() == true)
                {
                    await Task.Run(() => File.WriteAllBytes(dialog.FileName, pdfBytes));
                    await _dialog.ShowMessageAsync($"PDF report saved:\n{dialog.FileName}", "Report Saved");
                }
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to download report: {ex.Message}", "Error", true);
            }
        }
    }

    public class ReportTypeOption
    {
        public string Value { get; set; } = "";
        public string DisplayName { get; set; } = "";
    }
}

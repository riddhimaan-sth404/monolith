using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Extensions.Logging;
using MonolithGui.Models;
using MonolithGui.Services;

namespace MonolithGui.ViewModels
{
    public class ScanViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IDialogService _dialog;
        private readonly ILogger<ScanViewModel> _logger;

        public ObservableCollection<ScanResult> ScanResults { get; } = new ObservableCollection<ScanResult>();
        public ObservableCollection<ScanItem> ScanHistory { get; } = new ObservableCollection<ScanItem>();

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        private string _scanStatus = "Scanner Idle";
        public string ScanStatus
        {
            get => _scanStatus;
            set => SetProperty(ref _scanStatus, value);
        }

        private int _scanProgress;
        public int ScanProgress
        {
            get => _scanProgress;
            set => SetProperty(ref _scanProgress, value);
        }

        private string _scanPath = string.Empty;
        public string ScanPath
        {
            get => _scanPath;
            set => SetProperty(ref _scanPath, value);
        }

        private string? _activeScanId;

        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand CustomScanCommand { get; }
        public ICommand CancelScanCommand { get; }
        public ICommand RefreshHistoryCommand { get; }

        public ScanViewModel(IApiService api, IDialogService dialog, ILogger<ScanViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            QuickScanCommand = new RelayCommand(async () => await StartScan("quick"));
            FullScanCommand = new RelayCommand(async () => await StartScan("full"));
            CustomScanCommand = new RelayCommand(async () => await StartCustomScan());
            CancelScanCommand = new RelayCommand(async () => await CancelScan());
            RefreshHistoryCommand = new RelayCommand(async () => await LoadHistory());
        }

        private async Task StartScan(string scanType, List<string>? paths = null)
        {
            if (IsScanning) return;
            IsScanning = true;
            ScanStatus = $"Running {scanType.ToUpper()} scan...";
            ScanResults.Clear();

            try
            {
                var payload = new { scan_type = scanType, endpoint_id = "localhost", paths = paths ?? new List<string>() };
                var res = await _api.PostAsync<object, Dictionary<string, object>>("/scans", payload);

                string? scanId = null;
                if (res != null)
                {
                    if (res.TryGetValue("scan_id", out var sid) && sid is string s1) scanId = s1;
                    else if (res.TryGetValue("id", out var sid2) && sid2 is string s2) scanId = s2;
                }

                if (!string.IsNullOrEmpty(scanId))
                {
                    _activeScanId = scanId;
                    _ = PollScanProgress(scanId!);
                }
                else
                {
                    IsScanning = false;
                    ScanStatus = "Failed to initiate scan.";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to trigger scan type {Type}", scanType);
                IsScanning = false;
                ScanStatus = $"Scan trigger failed: {ex.Message}";
            }
        }

        private async Task StartCustomScan()
        {
            string? folder = null;
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Select File or Directory to Scan",
                    CheckFileExists = false,
                    ValidateNames = false,
                    FileName = "Select Folder or File"
                };
                if (dialog.ShowDialog() == true)
                {
                    folder = System.IO.Path.GetDirectoryName(dialog.FileName);
                    if (string.IsNullOrEmpty(folder)) folder = dialog.FileName;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "OpenFileDialog failed, falling back to InputDialog.");
                folder = await _dialog.ShowInputDialogAsync("Enter folder or file path to scan:", "Custom Scan", @"C:\Windows");
            }

            if (string.IsNullOrWhiteSpace(folder)) return;

            await StartScan("custom", new List<string> { folder.Trim() });
        }

        private async Task PollScanProgress(string scanId)
        {
            var startTime = DateTime.UtcNow;
            int consecutiveFailures = 0;
            while (IsScanning && _activeScanId == scanId)
            {
                if ((DateTime.UtcNow - startTime).TotalMinutes >= 5)
                {
                    ScanProgress = 0;
                    ScanStatus = "Scan Timed Out";
                    IsScanning = false;
                    break;
                }

                try
                {
                    var res = await _api.GetAsync<Dictionary<string, object>>($"/scans/{scanId}");
                    consecutiveFailures = 0;
                    if (res != null)
                    {
                        string status = string.Empty;
                        if (res.TryGetValue("status", out var stObj) && stObj is string stStr)
                        {
                            status = stStr;
                        }

                        if (res.TryGetValue("scanned_files", out var sfObj) && res.TryGetValue("total_files", out var tfObj))
                        {
                            long sf = Convert.ToInt64(sfObj);
                            long tf = Convert.ToInt64(tfObj);
                            if (tf > 0)
                            {
                                ScanProgress = Math.Min(99, (int)((sf * 100) / tf));
                            }
                        }

                        if (res.TryGetValue("details", out var detObj) && detObj != null)
                        {
                            try
                            {
                                var detailsStr = detObj.ToString();
                                if (!string.IsNullOrWhiteSpace(detailsStr))
                                {
                                    var details = Newtonsoft.Json.Linq.JObject.Parse(detailsStr);
                                    if (details["current_path"] != null)
                                    {
                                        ScanPath = details["current_path"]!.ToString();
                                    }

                                    if (status.Equals("completed", StringComparison.OrdinalIgnoreCase) && details["files"] != null)
                                    {
                                        var filesJson = details["files"]!.ToString();
                                        var list = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ScanResult>>(filesJson);
                                        if (list != null)
                                        {
                                            ScanResults.Clear();
                                            foreach (var r in list) ScanResults.Add(r);
                                        }
                                        OpenResultsInNotepad(filesJson);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Failed to parse scan details JSON.");
                            }
                        }

                        if (status.Equals("completed", StringComparison.OrdinalIgnoreCase))
                        {
                            ScanProgress = 100;
                            ScanStatus = "Scan Completed";
                            IsScanning = false;
                            await LoadHistory();
                            break;
                        }
                        else if (status.Equals("failed", StringComparison.OrdinalIgnoreCase) || status.Equals("cancelled", StringComparison.OrdinalIgnoreCase))
                        {
                            ScanProgress = 0;
                            ScanStatus = status.Equals("failed", StringComparison.OrdinalIgnoreCase) ? "Scan Failed (Go Scanner unavailable)" : "Scan Cancelled";
                            IsScanning = false;
                            await LoadHistory();
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    consecutiveFailures++;
                    if (consecutiveFailures >= 10)
                    {
                        ScanProgress = 0;
                        ScanStatus = $"Connection lost: {ex.Message}";
                        IsScanning = false;
                        break;
                    }
                }

                await Task.Delay(1500);
            }
        }

        private void OpenResultsInNotepad(string filesJson)
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("======================================================================");
                sb.AppendLine("                       MONOLITH EDR SCAN REPORT                       ");
                sb.AppendLine("======================================================================");
                sb.AppendLine($"Scan ID: {_activeScanId}");
                sb.AppendLine($"Timestamp: {DateTime.Now}");
                sb.AppendLine($"Scan Status: {ScanStatus}");
                sb.AppendLine("======================================================================");
                sb.AppendLine();

                var list = Newtonsoft.Json.Linq.JArray.Parse(filesJson);
                int cleanCount = 0, suspiciousCount = 0, maliciousCount = 0;

                foreach (var token in list)
                {
                    var verdict = token["verdict"]?.ToString() ?? "clean";
                    if (verdict.Equals("clean", StringComparison.OrdinalIgnoreCase)) cleanCount++;
                    else if (verdict.Equals("suspicious", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;
                    else if (verdict.Equals("malicious", StringComparison.OrdinalIgnoreCase)) maliciousCount++;
                }

                sb.AppendLine("VERDICT SUMMARY:");
                sb.AppendLine($"  Clean Files:      {cleanCount}");
                sb.AppendLine($"  Suspicious Files: {suspiciousCount}");
                sb.AppendLine($"  Malicious Files:  {maliciousCount}");
                sb.AppendLine($"  Total Scanned:    {list.Count}");
                sb.AppendLine("----------------------------------------------------------------------");
                sb.AppendLine();

                sb.AppendLine("DETAILED SCAN RESULTS:");
                foreach (var token in list)
                {
                    var path = token["file_path"]?.ToString() ?? token["path"]?.ToString() ?? "Unknown Path";
                    var name = token["file_name"]?.ToString() ?? token["name"]?.ToString() ?? "Unknown";
                    var size = token["file_size"]?.ToString() ?? "Unknown";
                    var verdict = token["verdict"]?.ToString() ?? "clean";
                    var score = token["score"]?.ToString() ?? "0.0";
                    var hScore = token["heuristic_score"]?.ToString() ?? "0.0";
                    var eScore = token["ember_score"]?.ToString() ?? "0.0";
                    var fScore = token["fusion_score"]?.ToString() ?? "0.0";
                    var quarantined = token["quarantined"]?.ToString() ?? "false";
                    var matchedRules = token["matched_rules"]?.ToString();

                    sb.AppendLine($"File Path:  {path}");
                    sb.AppendLine($"File Name:  {name}");
                    sb.AppendLine($"File Size:  {size} bytes");
                    sb.AppendLine($"Verdict:    {verdict.ToUpper()}");
                    sb.AppendLine($"Score:      {score} (Heuristics: {hScore}, EMBER: {eScore}, Fusion: {fScore})");
                    if (!string.IsNullOrEmpty(matchedRules) && matchedRules != "[]")
                    {
                        sb.AppendLine($"Matched Rules: {matchedRules}");
                    }
                    sb.AppendLine($"Quarantined: {quarantined}");
                    sb.AppendLine("----------------------------------------------------------------------");
                }

                var tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"ScanReport_{_activeScanId}_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                System.IO.File.WriteAllText(tempPath, sb.ToString());
                System.Diagnostics.Process.Start("notepad.exe", tempPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write or open scan report in Notepad.");
            }
        }

        private async Task CancelScan()
        {
            if (!IsScanning || string.IsNullOrEmpty(_activeScanId)) return;
            try
            {
                await _api.PostAsync<object, object>($"/scans/{_activeScanId}/cancel", new { });
                ScanStatus = "Scan Cancelled";
                IsScanning = false;
            }
            catch (Exception ex)
            {
                await _dialog.ShowMessageAsync($"Failed to cancel scan: {ex.Message}", "Error", true);
                IsScanning = false;
            }
        }

        public async Task LoadHistory()
        {
            try
            {
                var res = await _api.GetAsync<Dictionary<string, object>>("/scans");
                if (res != null && res.TryGetValue("scans", out var scansObj))
                {
                    var json = Newtonsoft.Json.JsonConvert.SerializeObject(scansObj);
                    var history = Newtonsoft.Json.JsonConvert.DeserializeObject<List<ScanItem>>(json);
                    if (history != null)
                    {
                        ScanHistory.Clear();
                        foreach (var h in history) ScanHistory.Add(h);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load scan history.");
            }
        }
    }
}

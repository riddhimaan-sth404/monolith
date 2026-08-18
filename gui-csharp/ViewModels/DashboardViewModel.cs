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
    public class DashboardViewModel : ViewModelBase
    {
        private readonly IApiService _api;
        private readonly IWebSocketService _ws;
        private readonly IDialogService _dialog;
        private readonly ILogger<DashboardViewModel> _logger;

        private DashboardSummary _summary = new DashboardSummary();
        public DashboardSummary Summary
        {
            get => _summary;
            set => SetProperty(ref _summary, value);
        }

        public ObservableCollection<string> LiveEvents { get; } = new ObservableCollection<string>();

        public ICommand RefreshCommand { get; }
        public ICommand TriggerQuickScanCommand { get; }
        public ICommand CancelScanCommand { get; }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        private int _scanProgress;
        public int ScanProgress
        {
            get => _scanProgress;
            set => SetProperty(ref _scanProgress, value);
        }

        private string _scanStatus = "Scanner Idle";
        public string ScanStatus
        {
            get => _scanStatus;
            set => SetProperty(ref _scanStatus, value);
        }

        private string _scanPath = string.Empty;
        public string ScanPath
        {
            get => _scanPath;
            set => SetProperty(ref _scanPath, value);
        }

        private string? _activeScanId;

        public DashboardViewModel(
            IApiService api,
            IWebSocketService ws,
            IDialogService dialog,
            ILogger<DashboardViewModel> logger)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _ws = ws ?? throw new ArgumentNullException(nameof(ws));
            _dialog = dialog ?? throw new ArgumentNullException(nameof(dialog));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            RefreshCommand = new RelayCommand(async () => await LoadDashboardData());
            TriggerQuickScanCommand = new RelayCommand(async () => await TriggerQuickScan());
            CancelScanCommand = new RelayCommand(async () => await CancelScan());

            _ws.OnEventReceived += HandleWsEvent;
        }

        public void Cleanup()
        {
            _ws.OnEventReceived -= HandleWsEvent;
        }

        public async Task LoadDashboardData()
        {
            IsLoading = true;
            try
            {
                var res = await _api.GetAsync<Dictionary<string, object>>("/dashboard");
                if (res != null)
                {
                    var newSummary = new DashboardSummary();
                    
                    // Parse agent status
                    bool agentRunning = false;
                    if (res.TryGetValue("agent", out var agentObj) && agentObj != null)
                    {
                        var agent = Newtonsoft.Json.Linq.JObject.FromObject(agentObj);
                        if (agent["running"] != null) agentRunning = (bool)agent["running"];
                    }

                    // Parse alerts
                    int activeAlerts = 0;
                    int criticalAlerts = 0;
                    int highAlerts = 0;
                    if (res.TryGetValue("alerts", out var alertsObj) && alertsObj != null)
                    {
                        var alerts = Newtonsoft.Json.Linq.JObject.FromObject(alertsObj);
                        if (alerts["active"] != null) activeAlerts = (int)alerts["active"];
                        if (alerts["critical"] != null) criticalAlerts = (int)alerts["critical"];
                        if (alerts["high"] != null) highAlerts = (int)alerts["high"];
                    }

                    // Parse events_today
                    int eventsToday = 0;
                    if (res.TryGetValue("events_today", out var eventsObj) && eventsObj != null)
                    {
                        eventsToday = Convert.ToInt32(eventsObj);
                    }

                    // Parse active scans
                    int activeScans = 0;
                    if (res.TryGetValue("active_scans", out var scansObj) && scansObj != null)
                    {
                        activeScans = Convert.ToInt32(scansObj);
                    }

                    // Calculate HealthScore
                    int health = 100;
                    if (!agentRunning)
                    {
                        health -= 50;
                    }
                    health -= (criticalAlerts * 15 + highAlerts * 5 + Math.Max(0, activeAlerts - criticalAlerts - highAlerts) * 2);
                    newSummary.HealthScore = Math.Max(0, Math.Min(100, health));
                    newSummary.ActiveEndpoints = agentRunning ? 1 : 0;
                    newSummary.OpenAlerts = activeAlerts;
                    newSummary.ThreatsBlocked = eventsToday;
                    newSummary.ActiveScans = activeScans;

                    Summary = newSummary;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load dashboard summary.");
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void HandleWsEvent(string jsonEvent)
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                LiveEvents.Insert(0, $"[{DateTime.Now:HH:mm:ss}] {jsonEvent}");
                if (LiveEvents.Count > 100) LiveEvents.RemoveAt(LiveEvents.Count - 1);
            });
        }

        private async Task TriggerQuickScan()
        {
            if (IsScanning) return;
            IsScanning = true;
            ScanStatus = "Running QUICK scan...";
            ScanPath = string.Empty;

            try
            {
                var payload = new { scan_type = "quick", endpoint_id = "localhost", paths = new List<string>() };
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
                _logger.LogError(ex, "Failed to trigger quick scan");
                IsScanning = false;
                ScanStatus = $"Scan trigger failed: {ex.Message}";
            }
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
                            status = stStr;

                        if (res.TryGetValue("scanned_files", out var sfObj) && res.TryGetValue("total_files", out var tfObj))
                        {
                            long sf = Convert.ToInt64(sfObj);
                            long tf = Convert.ToInt64(tfObj);
                            if (tf > 0)
                                ScanProgress = Math.Min(99, (int)((sf * 100) / tf));
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
                                        ScanPath = details["current_path"]!.ToString();
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
                            await LoadDashboardData();
                            break;
                        }
                        else if (status.Equals("failed", StringComparison.OrdinalIgnoreCase))
                        {
                            ScanProgress = 0;
                            ScanStatus = "Scan Failed";
                            IsScanning = false;
                            await LoadDashboardData();
                            break;
                        }
                        else if (status.Equals("cancelled", StringComparison.OrdinalIgnoreCase))
                        {
                            ScanProgress = 0;
                            ScanStatus = "Scan Cancelled";
                            IsScanning = false;
                            await LoadDashboardData();
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

        private async Task CancelScan()
        {
            if (!IsScanning || string.IsNullOrEmpty(_activeScanId)) return;
            try
            {
                await _api.PostAsync<object, object>($"/scans/{_activeScanId}/cancel", new { });
                ScanStatus = "Cancelling...";
                IsScanning = false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cancel scan");
                IsScanning = false;
            }
        }
    }
}

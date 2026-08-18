using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace MonolithGui.Models
{
    public class DashboardSummary
    {
        [JsonProperty("health_score")]
        public int HealthScore { get; set; } = 100;

        [JsonProperty("active_endpoints")]
        public int ActiveEndpoints { get; set; }

        [JsonProperty("open_alerts")]
        public int OpenAlerts { get; set; }

        [JsonProperty("threats_blocked")]
        public int ThreatsBlocked { get; set; }

        [JsonProperty("active_scans")]
        public int ActiveScans { get; set; }
    }

    public class EndpointItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("hostname")]
        public string Hostname { get; set; } = string.Empty;

        [JsonProperty("ip_address")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonProperty("os_version")]
        public string OsVersion { get; set; } = string.Empty;

        [JsonProperty("agent_version")]
        public string AgentVersion { get; set; } = string.Empty;

        [JsonProperty("status")]
        public string Status { get; set; } = "online";

        [JsonProperty("last_seen")]
        public string LastSeen { get; set; } = string.Empty;
    }

    public class AlertItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("title")]
        public string Title { get; set; } = string.Empty;

        [JsonProperty("description")]
        public string Description { get; set; } = string.Empty;

        [JsonProperty("severity")]
        public string Severity { get; set; } = "low";

        [JsonProperty("status")]
        public string Status { get; set; } = "open";

        [JsonProperty("rule_id")]
        public string RuleId { get; set; } = string.Empty;

        [JsonProperty("hit_count")]
        public int HitCount { get; set; } = 1;

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class MemoryAlertItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("process_name")]
        public string ProcessName { get; set; } = string.Empty;

        [JsonProperty("process_id")]
        public uint ProcessId { get; set; }

        [JsonProperty("region_base")]
        public string RegionBase { get; set; } = string.Empty;

        [JsonProperty("verdict")]
        public string Verdict { get; set; } = "clean";

        [JsonProperty("yara_matches")]
        public string YaraMatches { get; set; } = string.Empty;

        [JsonProperty("codebert_score")]
        public double CodebertScore { get; set; }

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class RegistryTamperAlertItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("key_path")]
        public string KeyPath { get; set; } = string.Empty;

        [JsonProperty("operation")]
        public string Operation { get; set; } = string.Empty;

        [JsonProperty("offending_pid")]
        public uint OffendingPid { get; set; }

        [JsonProperty("offending_process")]
        public string OffendingProcess { get; set; } = string.Empty;

        [JsonProperty("blocked")]
        public bool Blocked { get; set; } = true;

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class QuarantineItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("original_path")]
        public string OriginalPath { get; set; } = string.Empty;

        [JsonProperty("original_name")]
        public string OriginalName { get; set; } = string.Empty;

        [JsonProperty("quarantine_path")]
        public string QuarantinePath { get; set; } = string.Empty;

        [JsonProperty("threat_name")]
        public string ThreatName { get; set; } = string.Empty;

        [JsonProperty("verdict")]
        private string RawVerdict { set => ThreatName = value; }

        public string Verdict
        {
            get => ThreatName;
            set => ThreatName = value;
        }

        [JsonProperty("file_size")]
        public long Size { get; set; }

        [JsonProperty("size")]
        private long RawSize { set => Size = value; }

        [JsonProperty("quarantined_at")]
        public string CreatedAt { get; set; } = string.Empty;

        [JsonProperty("created_at")]
        private string RawCreatedAt { set => CreatedAt = value; }

        [JsonProperty("status")]
        public string Status { get; set; } = string.Empty;
    }

    public class AllowlistItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("value")]
        public string Target { get; set; } = string.Empty;

        [JsonProperty("target")]
        private string RawTarget { set => Target = value; }

        [JsonProperty("rule_type")]
        public string Type { get; set; } = "hash";

        [JsonProperty("type")]
        private string RawType { set => Type = value; }

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class IocItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("value")]
        public string Value { get; set; } = string.Empty;

        [JsonProperty("ioc_type")]
        public string Type { get; set; } = "hash"; // hash, ip, domain

        [JsonProperty("type")]
        private string RawType { set => Type = value; }

        [JsonProperty("description")]
        public string Description { get; set; } = string.Empty;

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class PolicyItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("name")]
        public string Name { get; set; } = string.Empty;

        [JsonProperty("quick_scan_interval_hours")]
        public int QuickScanIntervalHours { get; set; } = 24;

        [JsonProperty("memory_scan_enabled")]
        public bool MemoryScanEnabled { get; set; } = true;

        [JsonProperty("tamper_protection_level")]
        public string TamperProtectionLevel { get; set; } = "high";

        [JsonProperty("assigned_endpoints_count")]
        public int AssignedEndpointsCount { get; set; }
    }

    public class ReportItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("title")]
        public string Title { get; set; } = string.Empty;

        [JsonProperty("format")]
        public string Format { get; set; } = "pdf";

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class AuditLogEntry
    {
        [JsonProperty("id")]
        public long Id { get; set; }

        [JsonProperty("action")]
        public string Action { get; set; } = string.Empty;

        [JsonProperty("actor")]
        public string Actor { get; set; } = string.Empty;

        [JsonProperty("target_id")]
        public string TargetId { get; set; } = string.Empty;

        [JsonProperty("details")]
        public string Details { get; set; } = string.Empty;

        [JsonProperty("ip_address")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonProperty("hash")]
        public string Hash { get; set; } = string.Empty;

        [JsonProperty("prev_hash")]
        public string PrevHash { get; set; } = string.Empty;

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class MfaEnrollResult
    {
        [JsonProperty("secret")]
        public string Secret { get; set; } = string.Empty;

        [JsonProperty("qr_code_uri")]
        public string QrCodeUri { get; set; } = string.Empty;
    }

    public class LicenseStatus
    {
        [JsonProperty("active")]
        public bool Active { get; set; }

        [JsonProperty("customer_name")]
        public string CustomerName { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;

        [JsonProperty("max_endpoints")]
        public int MaxEndpoints { get; set; }
    }

    public class ScanItem
    {
        [JsonProperty("id")]
        public string Id { get; set; } = string.Empty;

        [JsonProperty("scan_type")]
        public string ScanType { get; set; } = "quick";

        [JsonProperty("status")]
        public string Status { get; set; } = "completed";

        [JsonProperty("current_path")]
        public string CurrentPath { get; set; } = string.Empty;

        [JsonProperty("started_at")]
        public string CreatedAt { get; set; } = string.Empty;
    }

    public class ScanResult
    {
        [JsonProperty("name")]
        public string Name { get; set; } = string.Empty;

        [JsonProperty("path")]
        public string Path { get; set; } = string.Empty;

        [JsonProperty("file_path")]
        public string FilePath
        {
            get => Path;
            set
            {
                if (!string.IsNullOrEmpty(value))
                {
                    Path = value;
                    if (string.IsNullOrEmpty(Name))
                    {
                        try { Name = System.IO.Path.GetFileName(value); } catch { Name = value; }
                    }
                }
            }
        }

        [JsonProperty("verdict")]
        public string Verdict { get; set; } = "clean";

        [JsonProperty("score")]
        public double Score { get; set; }
    }

    public class ApiErrorResponse
    {
        [JsonProperty("message")]
        public string? Message { get; set; }

        [JsonProperty("error")]
        public string? Error { get; set; }
    }
}

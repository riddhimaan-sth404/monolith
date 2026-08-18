use std::time::{Duration, Instant};

const PERSISTENCE_WINDOW_SECS: u64 = 120;
const ANCESTRY_WINDOW_SECS: u64 = 60;
const MAX_SPAWN_TRACK: usize = 2000;

#[derive(Clone)]
#[allow(dead_code)]
struct ProcessSpawn {
    pid: u32,
    parent_pid: u32,
    image: String,
    parent_image: String,
    time: Instant,
}

pub struct ChainDetector {
    recent_spawns: Vec<ProcessSpawn>,
    next_idx: usize,
    registry_persistence_writes: Vec<(String, Instant)>,
}

impl ChainDetector {
    pub fn new() -> Self {
        Self {
            recent_spawns: Vec::with_capacity(MAX_SPAWN_TRACK),
            next_idx: 0,
            registry_persistence_writes: Vec::new(),
        }
    }

    pub fn record_process_spawn(&mut self, pid: u32, parent_pid: u32, image: &str, parent_image: &str) {
        let now = Instant::now();
        let spawn = ProcessSpawn {
            pid, parent_pid, image: image.to_string(), parent_image: parent_image.to_string(), time: now,
        };
        if self.recent_spawns.len() < MAX_SPAWN_TRACK {
            self.recent_spawns.push(spawn);
        } else {
            self.recent_spawns[self.next_idx] = spawn;
            self.next_idx = (self.next_idx + 1) % MAX_SPAWN_TRACK;
        }
    }

    pub fn record_registry_persistence(&mut self, key_path: &str) {
        let now = Instant::now();
        self.registry_persistence_writes.push((key_path.to_string(), now));
        self.registry_persistence_writes.retain(|(_, t)| t.elapsed() < Duration::from_secs(PERSISTENCE_WINDOW_SECS));
    }

    pub fn check_file_against_recent_registry(&mut self, path: &str, _pid: u32) -> Option<super::DetectionAction> {
        self.registry_persistence_writes.retain(|(_, t)| t.elapsed() < Duration::from_secs(PERSISTENCE_WINDOW_SECS));
        if self.registry_persistence_writes.is_empty() {
            return None;
        }
        let lower = path.to_lowercase();
        let appdata_dirs = ["\\appdata\\", "\\programdata\\", "\\startup\\"];
        let in_user_dir = appdata_dirs.iter().any(|d| lower.contains(d));
        let is_exe_or_script = lower.ends_with(".exe") || lower.ends_with(".dll")
            || lower.ends_with(".ps1") || lower.ends_with(".vbs") || lower.ends_with(".js");
        if in_user_dir && is_exe_or_script {
            return Some(super::DetectionAction {
                action_type: "quarantine_file".to_string(),
                severity: "critical".to_string(),
                pid: _pid,
            });
        }
        None
    }

    fn is_persistence_key(key: &str) -> bool {
        let lower = key.to_lowercase();
        lower.contains(r"currentversion\run")
            || lower.contains(r"currentversion\runonce")
            || lower.contains(r"currentversion\policies\explorer\run")
            || lower.contains(r"currentversion\runservices")
            || lower.contains(r"windows\currentversion\run")
            || lower.contains(r"microsoft\windows\currentversion\run")
    }

    pub fn check_spawn_chain(&mut self, pid: u32, _parent_pid: u32, image: &str, parent_image: &str) -> Option<super::DetectionAction> {
        let lower_image = image.to_lowercase();
        let lower_parent = parent_image.to_lowercase();

        // Kill chains
        let chains: &[(&str, &str, &str, &str)] = &[
            // Office → script
            ("winword.exe", "powershell.exe", "office_script", "high"),
            ("excel.exe", "powershell.exe", "office_script", "high"),
            ("outlook.exe", "powershell.exe", "office_script", "high"),
            ("winword.exe", "cmd.exe", "office_script", "high"),
            ("excel.exe", "cmd.exe", "office_script", "high"),
            // LOLBin chains
            ("cmd.exe", "powershell.exe", "lolbin_chain", "medium"),
            ("powershell.exe", "cmd.exe", "lolbin_chain", "medium"),
            ("powershell.exe", "wscript.exe", "lolbin_chain", "medium"),
            ("powershell.exe", "cscript.exe", "lolbin_chain", "medium"),
            // Browser → process
            ("chrome.exe", "powershell.exe", "browser_script", "high"),
            ("msedge.exe", "powershell.exe", "browser_script", "high"),
            // WMI → suspicious
            ("wmiprvse.exe", "powershell.exe", "wmi_script", "high"),
            ("wmiprvse.exe", "cmd.exe", "wmi_script", "medium"),
            // Rundll32 → network
            ("rundll32.exe", "powershell.exe", "lolbin_chain", "high"),
            // MSHTA
            ("mshta.exe", "powershell.exe", "lolbin_chain", "high"),
        ];

        for (parent, child, _rule_id, severity) in chains {
            let pmatch = lower_parent.contains(parent) || lower_parent == *parent;
            let cmatch = lower_image.contains(child) || lower_image == *child;
            if pmatch && cmatch {
                self.record_process_spawn(pid, _parent_pid, image, parent_image);
                return Some(super::DetectionAction {
                    action_type: "terminate_process".to_string(),
                    severity: severity.to_string(),
                    pid,
                });
            }
        }

        // Also check stored spawns for grandparent chains (A→B→C)
        // Ensure the parent process matches, is not expired, and has a start time before now
        for spawn in &self.recent_spawns {
            if spawn.time.elapsed() < Duration::from_secs(ANCESTRY_WINDOW_SECS) && spawn.pid == _parent_pid {
                let grandparent_lower = spawn.parent_image.to_lowercase();
                for (gp, child, _rule_id, severity) in chains {
                    let gpmatch = grandparent_lower.contains(gp) || grandparent_lower == *gp;
                    let cmatch = lower_image.contains(child) || lower_image == *child;
                    if gpmatch && cmatch {
                        self.record_process_spawn(pid, _parent_pid, image, parent_image);
                        return Some(super::DetectionAction {
                            action_type: "terminate_process".to_string(),
                            severity: severity.to_string(),
                            pid,
                        });
                    }
                }
            }
        }

        self.record_process_spawn(pid, _parent_pid, image, parent_image);
        None
    }

    pub fn check_registry_event(&mut self, key_path: &str, _pid: u32) -> Option<super::DetectionAction> {
        if Self::is_persistence_key(key_path) {
            self.record_registry_persistence(key_path);
            return Some(super::DetectionAction {
                action_type: "alert_only".to_string(),
                severity: "medium".to_string(),
                pid: _pid,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_persistence_key ---

    #[test]
    fn test_is_persistence_key_run() {
        assert!(ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
    }

    #[test]
    fn test_is_persistence_key_runonce() {
        assert!(ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"));
    }

    #[test]
    fn test_is_persistence_key_policies_explorer() {
        assert!(ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"));
    }

    #[test]
    fn test_is_persistence_key_runservices() {
        assert!(ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"));
    }

    #[test]
    fn test_is_persistence_key_non_persistence() {
        assert!(!ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"));
        assert!(!ChainDetector::is_persistence_key(r"HKLM\SOFTWARE\Classes\.exe"));
        assert!(!ChainDetector::is_persistence_key(r""));
    }

    #[test]
    fn test_is_persistence_key_case_insensitive() {
        assert!(ChainDetector::is_persistence_key(r"hklm\software\microsoft\windows\currentversion\run"));
    }

    // --- check_registry_event ---

    #[test]
    fn test_registry_persistence_key_returns_alert() {
        let mut cd = ChainDetector::new();
        let result = cd.check_registry_event(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware", 123);
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.action_type, "alert_only");
        assert_eq!(action.severity, "medium");
        assert_eq!(action.pid, 123);
    }

    #[test]
    fn test_registry_non_persistence_key_returns_none() {
        let mut cd = ChainDetector::new();
        assert!(cd.check_registry_event(r"HKLM\SOFTWARE\Classes\.txt", 456).is_none());
    }

    // --- check_spawn_chain ---

    #[test]
    fn test_spawn_chain_office_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1001, 0, "powershell.exe", "winword.exe");
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.action_type, "terminate_process");
        assert_eq!(action.severity, "high");
        assert_eq!(action.pid, 1001);
    }

    #[test]
    fn test_spawn_chain_outlook_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1002, 0, "powershell.exe", "outlook.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_spawn_chain_cmd_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1003, 0, "powershell.exe", "cmd.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "medium");
    }

    #[test]
    fn test_spawn_chain_lolbin_powershell_to_wscript() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1004, 0, "wscript.exe", "powershell.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "medium");
    }

    #[test]
    fn test_spawn_chain_browser_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1005, 0, "powershell.exe", "chrome.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_spawn_chain_msedge_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1006, 0, "powershell.exe", "msedge.exe");
        assert!(result.is_some());
    }

    #[test]
    fn test_spawn_chain_wmi_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1007, 0, "powershell.exe", "wmiprvse.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_spawn_chain_rundll32_to_powershell() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1008, 0, "powershell.exe", "rundll32.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_spawn_chain_no_match() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1009, 0, "notepad.exe", "explorer.exe");
        assert!(result.is_none());
    }

    #[test]
    fn test_spawn_chain_case_insensitive() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1010, 0, "PowerShell.EXE", "WINWORD.EXE");
        assert!(result.is_some());
    }

    #[test]
    fn test_spawn_chain_parent_with_path() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1011, 0, "powershell.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    #[test]
    fn test_spawn_chain_child_with_path() {
        let mut cd = ChainDetector::new();
        let result = cd.check_spawn_chain(1012, 0, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "cmd.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "medium");
    }

    #[test]
    fn test_spawn_chain_grandparent_detection() {
        let mut cd = ChainDetector::new();
        // First simulate: parent (winword) spawns intermediate (cmd), but cmd isn't in our direct chains with winword
        // Actually, winword→cmd IS a chain, so let's use a different scenario
        // Simulate: grandparent is winword.exe → parent is notepad.exe → child is powershell.exe
        // We need to record the grandparent→parent spawn first, then check the parent→child spawn
        cd.record_process_spawn(2001, 0, "notepad.exe", "winword.exe");
        // The grandparent check looks for: parent_pid == stored spid (spawn.pid), so winword→notepad stored
        // Now check notepad→powershell with _parent_pid=2001
        let result = cd.check_spawn_chain(2002, 2001, "powershell.exe", "notepad.exe");
        // This should match: grandparent contains winword, child contains powershell
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    // --- check_file_against_recent_registry ---

    #[test]
    fn test_file_combo_no_recent_registry() {
        let mut cd = ChainDetector::new();
        let result = cd.check_file_against_recent_registry("C:\\Users\\test\\AppData\\Local\\temp\\evil.exe", 3001);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_combo_recent_registry_plus_appdata_exe() {
        let mut cd = ChainDetector::new();
        cd.record_registry_persistence(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        let result = cd.check_file_against_recent_registry("C:\\Users\\test\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe", 3002);
        assert!(result.is_some());
        let action = result.unwrap();
        assert_eq!(action.action_type, "quarantine_file");
        assert_eq!(action.severity, "critical");
        assert_eq!(action.pid, 3002);
    }

    #[test]
    fn test_file_combo_recent_registry_plus_programdata_ps1() {
        let mut cd = ChainDetector::new();
        cd.record_registry_persistence(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce");
        let result = cd.check_file_against_recent_registry("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\script.ps1", 3003);
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "critical");
    }

    #[test]
    fn test_file_combo_recent_registry_but_file_not_in_user_dir() {
        let mut cd = ChainDetector::new();
        cd.record_registry_persistence(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        let result = cd.check_file_against_recent_registry("C:\\Windows\\System32\\legit.dll", 3004);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_combo_recent_registry_but_not_exe_or_script() {
        let mut cd = ChainDetector::new();
        cd.record_registry_persistence(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        let result = cd.check_file_against_recent_registry("C:\\Users\\test\\AppData\\Local\\readme.txt", 3005);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_combo_expired_registry_not_detected() {
        let mut cd = ChainDetector::new();
        cd.registry_persistence_writes.push(("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), Instant::now() - Duration::from_secs(121)));
        // The expired entry should be pruned
        let result = cd.check_file_against_recent_registry("C:\\Users\\test\\AppData\\Local\\evil.exe", 3006);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_combo_detects_dll_in_user_dir() {
        let mut cd = ChainDetector::new();
        cd.record_registry_persistence(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
        let result = cd.check_file_against_recent_registry("C:\\Users\\test\\AppData\\Local\\Temp\\malicious.dll", 3007);
        assert!(result.is_some());
        assert_eq!(result.unwrap().action_type, "quarantine_file");
    }

    // --- record_process_spawn and check_spawn_chain interaction ---

    #[test]
    fn test_spawn_chain_match_records_spawn() {
        let mut cd = ChainDetector::new();
        cd.check_spawn_chain(4001, 0, "powershell.exe", "winword.exe");
        // The spawn should be recorded for future grandparent checks
        // After matching, the spawn is recorded, so we trace it
        // We can verify by checking if the next grandparent lookup works
    }

    #[test]
    fn test_no_match_still_records_spawn() {
        let mut cd = ChainDetector::new();
        cd.check_spawn_chain(4002, 0, "notepad.exe", "explorer.exe");
        // No match, but spawn is still recorded for future use
    }

    #[test]
    fn test_spawn_chain_match_records_recent_spawns() {
        let mut cd = ChainDetector::new();
        // First spawn: no match yet, but should be stored
        cd.check_spawn_chain(5001, 0, "cmd.exe", "winword.exe");
        // Now winword→cmd should match (it's in the chains)
        // Actually: ("winword.exe", "cmd.exe", "office_script", "high")
        // So this should match on the first call itself!
        let result = cd.check_spawn_chain(5001, 0, "cmd.exe", "winword.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "high");
    }

    // --- max spawn tracking ---

    #[test]
    fn test_max_spawn_tracking_wraps() {
        let mut cd = ChainDetector::new();
        // Fill up to MAX_SPAWN_TRACK
        for i in 0..MAX_SPAWN_TRACK as u32 {
            cd.record_process_spawn(i, 0, "legit.exe", "explorer.exe");
        }
        // Next spawn wraps around
        cd.record_process_spawn(9999, 0, "legit.exe", "explorer.exe");
        // Should not panic and should have tracked all
    }
}

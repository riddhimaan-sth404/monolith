#![allow(unsafe_code)]
#![allow(missing_docs)]

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use monolith_protobuf::proto::v1::PcProfile;

const IDLE_THRESHOLD_SECS: u64 = 300;
const DEEP_IDLE_THRESHOLD_SECS: u64 = 1800;
const PERFORMANCE_CPU_THRESHOLD: f64 = 80.0;

#[repr(C)]
struct LastInputInfo {
    cb_size: u32,
    dw_time: u32,
}

#[repr(C)]
struct SystemPowerStatus {
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
    battery_full_life_time: u32,
}

unsafe extern "system" {
    fn GetForegroundWindow() -> isize;
    fn GetWindowThreadProcessId(hwnd: isize, lpdw_process_id: *mut u32) -> u32;
    fn GetLastInputInfo(plii: *mut LastInputInfo) -> i32;
    fn GetSystemPowerStatus(lp_system_power_status: *mut SystemPowerStatus) -> i32;
}

pub struct SystemStateMonitor {
    last_cpu_sample: AtomicU64,
    last_idle_sample: AtomicU64,
    current_profile: AtomicI32,
    last_foreground_pid: u32,
    last_activity_tick: u32,
    cached_game_list: Vec<String>,
}

impl SystemStateMonitor {
    pub fn new() -> Self {
        let (idle, kernel, user) = Self::get_cpu_times();
        let start = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() };
        Self {
            last_cpu_sample: AtomicU64::new(kernel + user),
            last_idle_sample: AtomicU64::new(idle),
            current_profile: AtomicI32::new(PcProfile::Balanced as i32),
            last_foreground_pid: 0,
            last_activity_tick: start,
            cached_game_list: vec![
                "csgo.exe",
                "dota2.exe",
                "lol.exe",
                "LeagueClient.exe",
                "overwatch.exe",
                "fortnite.exe",
                "Valorant.exe",
                "VALORANT-Win64-Shipping.exe",
                "RustClient.exe",
                "Minecraft.exe",
                "javaw.exe",
                "steam.exe",
                "epicgameslauncher.exe",
                "battle.net.exe",
                "GTA5.exe",
                "RDR2.exe",
                "Cyberpunk2077.exe",
                "eldenring.exe",
                "CallOfDuty.exe",
                "ModernWarfare.exe",
                "Apex Legends.exe",
                "r5apex.exe",
                "RainbowSix.exe",
                "RainbowSix_Vulkan.exe",
                "Destiny2.exe",
                "Wow.exe",
                "WorldOfWarcraft.exe",
                "StarCraftII.exe",
                "DiabloIII64.exe",
                "Hearthstone.exe",
                "HeroesOfTheStorm64.exe",
                "PUBG.exe",
                "TslGame.exe",
                "RocketLeague.exe",
                "FIFA22.exe",
                "FIFA23.exe",
            ]
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect(),
        }
    }

    pub fn current_profile(&self) -> PcProfile {
        match self.current_profile.load(Ordering::Relaxed) {
            1 => PcProfile::Performance,
            2 => PcProfile::Balanced,
            3 => PcProfile::Gaming,
            4 => PcProfile::Presentation,
            5 => PcProfile::Battery,
            6 => PcProfile::Idle,
            _ => PcProfile::Unspecified,
        }
    }

    pub fn poll(&mut self) -> PcProfile {
        let profile = self.detect_profile();
        self.current_profile
            .store(profile as i32, Ordering::Relaxed);
        profile
    }

    fn detect_profile(&mut self) -> PcProfile {
        if self.is_gaming() {
            return PcProfile::Gaming;
        }
        if self.is_presentation_mode() {
            return PcProfile::Presentation;
        }
        if self.is_on_battery() {
            return PcProfile::Battery;
        }
        let idle_secs = self.idle_seconds();
        if idle_secs > DEEP_IDLE_THRESHOLD_SECS {
            return PcProfile::Idle;
        }
        if self.is_high_cpu_load() {
            return PcProfile::Performance;
        }
        if idle_secs > IDLE_THRESHOLD_SECS {
            return PcProfile::Idle;
        }
        PcProfile::Balanced
    }

    fn is_gaming(&mut self) -> bool {
        #[cfg(windows)]
        {
            unsafe {
                let hwnd = GetForegroundWindow();
                if hwnd == 0 {
                    return false;
                }

                let mut pid: u32 = 0;
                GetWindowThreadProcessId(hwnd, &mut pid);
                if pid == 0 {
                    return false;
                }

                if pid != self.last_foreground_pid {
                    self.last_foreground_pid = pid;
                    self.last_activity_tick =
                        windows_sys::Win32::System::SystemInformation::GetTickCount();
                }

                let handle = windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
                    0,
                    pid,
                );
                if handle.is_null() {
                    return false;
                }

                let mut exe_buf = [0u16; 260];
                let exe_len: u32 = 260;
                let result = windows_sys::Win32::System::ProcessStatus::GetModuleBaseNameW(
                    handle,
                    std::ptr::null_mut(),
                    exe_buf.as_mut_ptr(),
                    exe_len,
                );

                let _ = windows_sys::Win32::Foundation::CloseHandle(handle);

                if result == 0 {
                    return false;
                }

                let exe_name = String::from_utf16_lossy(&exe_buf[..result as usize])
                    .trim_end_matches('\0')
                    .to_lowercase();

                return self.cached_game_list.iter().any(|g| exe_name.contains(g));
            }
        }

        #[cfg(not(windows))]
        {
            false
        }
    }

    fn is_presentation_mode(&self) -> bool {
        let key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\PresentationSettings";
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = std::ffi::OsStr::new(key).encode_wide().chain([0]).collect();

        let mut hkey = std::ptr::null_mut();
        let result = unsafe {
            windows_sys::Win32::System::Registry::RegOpenKeyExW(
                windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
                wide.as_ptr(),
                0,
                windows_sys::Win32::System::Registry::KEY_READ,
                &mut hkey,
            )
        };

        if result == 0 && !hkey.is_null() {
            unsafe {
                let _ = windows_sys::Win32::System::Registry::RegCloseKey(hkey);
            }
            return true;
        }
        false
    }

    fn is_on_battery(&self) -> bool {
        #[cfg(windows)]
        {
            let mut status = std::mem::MaybeUninit::<SystemPowerStatus>::uninit();
            unsafe {
                if GetSystemPowerStatus(status.as_mut_ptr()) != 0 {
                    return status.assume_init().ac_line_status == 0;
                }
            }
        }
        false
    }

    fn idle_seconds(&mut self) -> u64 {
        #[cfg(windows)]
        {
            let now = unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount() };

            let mut lii = std::mem::MaybeUninit::<LastInputInfo>::uninit();
            unsafe {
                (*lii.as_mut_ptr()).cb_size = size_of::<LastInputInfo>() as u32;
                if GetLastInputInfo(lii.as_mut_ptr()) != 0 {
                    let lii = lii.assume_init();
                    if lii.dw_time > 0 && lii.dw_time <= now {
                        let idle = (now - lii.dw_time) as u64 / 1000;
                        if idle > 0 {
                            return idle;
                        }
                    }
                }
            }

            let fg_pid = unsafe {
                let mut pid: u32 = 0;
                let hwnd = GetForegroundWindow();
                if hwnd != 0 {
                    GetWindowThreadProcessId(hwnd, &mut pid);
                }
                pid
            };

            if fg_pid != 0 {
                if fg_pid != self.last_foreground_pid {
                    self.last_foreground_pid = fg_pid;
                    self.last_activity_tick = now;
                }
            }

            if now >= self.last_activity_tick {
                return (now - self.last_activity_tick) as u64 / 1000;
            }
        }
        0
    }

    fn is_high_cpu_load(&self) -> bool {
        let (idle, kernel, user) = Self::get_cpu_times();
        let total = kernel + user;
        let prev_total = self.last_cpu_sample.swap(total, Ordering::Relaxed);
        let prev_idle = self.last_idle_sample.swap(idle, Ordering::Relaxed);

        let total_delta = total.saturating_sub(prev_total);
        let idle_delta = idle.saturating_sub(prev_idle);

        if total_delta == 0 {
            return false;
        }

        let busy_delta = total_delta.saturating_sub(idle_delta);
        let usage = (busy_delta as f64 / total_delta as f64) * 100.0;
        usage > PERFORMANCE_CPU_THRESHOLD
    }

    #[cfg(windows)]
    fn get_cpu_times() -> (u64, u64, u64) {
        let mut idle = std::mem::MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
        let mut kernel =
            std::mem::MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
        let mut user = std::mem::MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();

        unsafe {
            if windows_sys::Win32::System::Threading::GetSystemTimes(
                idle.as_mut_ptr(),
                kernel.as_mut_ptr(),
                user.as_mut_ptr(),
            ) != 0
            {
                let idle = idle.assume_init();
                let kernel = kernel.assume_init();
                let user = user.assume_init();
                let idle_val = (idle.dwHighDateTime as u64) << 32 | idle.dwLowDateTime as u64;
                let kernel_val = (kernel.dwHighDateTime as u64) << 32 | kernel.dwLowDateTime as u64;
                let user_val = (user.dwHighDateTime as u64) << 32 | user.dwLowDateTime as u64;
                (idle_val, kernel_val, user_val)
            } else {
                (0, 0, 0)
            }
        }
    }

    #[cfg(not(windows))]
    fn get_cpu_times() -> (u64, u64, u64) {
        (0, 0, 0)
    }
}

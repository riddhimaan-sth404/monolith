use chrono::Utc;
use prost_types::Timestamp;
use std::os::windows::ffi::OsStringExt;

use monolith_protobuf::proto::v1::{self, event::Payload};

use crate::etw_manager::EtwDispatchContext;

pub fn handle_event(event_id: u16, pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    match event_id {
        1 => handle_process_start(pid, data, ctx),
        2 => handle_process_stop(pid, data, ctx),
        _ => {}
    }
}

fn parse_unicode_at_end(data: &[u8]) -> String {
    if data.len() < 4 {
        return String::new();
    }
    let start = data.len() - (data.len() % 2);
    if start < 2 {
        return String::new();
    }
    let mut chars = Vec::new();
    let mut i = start;
    while i >= 2 {
        let code = u16::from_le_bytes([data[i - 2], data[i - 1]]);
        if code == 0 {
            break;
        }
        chars.push(code);
        i -= 2;
        if chars.len() > 260 {
            break;
        }
    }
    chars.reverse();
    if chars.is_empty() {
        return String::new();
    }
    <std::ffi::OsString as OsStringExt>::from_wide(&chars)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_process_create_buf(parent_pid: u32, image: &str) -> Vec<u8> {
        let mut buf = vec![0u8; 48];
        buf[12..16].copy_from_slice(&parent_pid.to_le_bytes());
        let encoded: Vec<u16> = image.encode_utf16().collect();
        let total = 48 + 2 + encoded.len() * 2;
        let total = if total % 2 == 0 { total } else { total + 1 };
        buf.resize(total, 0);
        for (i, &cp) in encoded.iter().enumerate() {
            let off = 48 + 2 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        buf
    }

    #[test]
    fn test_parse_unicode_at_end_empty() {
        assert_eq!(parse_unicode_at_end(&[]), "");
    }

    #[test]
    fn test_parse_unicode_at_end_short() {
        assert_eq!(parse_unicode_at_end(&[0u8; 2]), "");
    }

    #[test]
    fn test_parse_unicode_at_end_valid() {
        let encoded: Vec<u16> = "C:\\Windows\\System32\\cmd.exe".encode_utf16().collect();
        let mut buf = vec![0u8; 8 + encoded.len() * 2];
        for (i, &cp) in encoded.iter().enumerate() {
            let off = 8 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        let result = parse_unicode_at_end(&buf);
        assert_eq!(result, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn test_parse_unicode_at_end_long_truncated() {
        let long = format!("C:\\{}", "a".repeat(300));
        let encoded: Vec<u16> = long.encode_utf16().collect();
        let mut buf = vec![0u8; 8 + encoded.len() * 2];
        for (i, &cp) in encoded.iter().enumerate() {
            let off = 8 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        assert!(parse_unicode_at_end(&buf).len() <= 261);
    }

    #[test]
    fn test_handle_process_start_creates_event() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_process_create_buf(888, "C:\\tools\\malware.exe");
        handle_event(1, 777, &buf, &ctx);
        let events = buffer.blocking_lock();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, v1::EventType::ProcessCreate as i32);
        if let Some(Payload::ProcessCreate(ref p)) = ev.payload {
            let proc = p.process.as_ref().unwrap();
            assert_eq!(proc.pid, 777);
            assert_eq!(proc.parent_pid, 888);
            assert_eq!(proc.path, "C:\\tools\\malware.exe");
        } else {
            panic!("expected ProcessCreate payload");
        }
    }

    #[test]
    fn test_handle_process_stop_creates_event() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(2, 555, &[0u8; 4], &ctx);
        let events = buffer.blocking_lock();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, v1::EventType::ProcessExit as i32);
        if let Some(Payload::ProcessExit(ref p)) = ev.payload {
            assert_eq!(p.pid, 555);
        } else {
            panic!("expected ProcessExit payload");
        }
    }

    #[test]
    fn test_handle_process_unknown_event_id() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(99, 666, &[0u8; 4], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }

    #[test]
    fn test_handle_process_start_short_data() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(1, 444, &[0u8; 10], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }
}

fn handle_process_start(pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    if data.len() < 48 {
        return;
    }
    let parent_pid = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let image_path = parse_unicode_at_end(data);
    let image_name = image_path
        .rsplit('\\')
        .next()
        .unwrap_or(&image_path)
        .to_string();

    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let proto_event = v1::Event {
        id: Some(v1::Uuid {
            value: uuid::Uuid::new_v4().as_bytes().to_vec(),
        }),
        endpoint_id: None,
        event_type: v1::EventType::ProcessCreate.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::ProcessCreate(v1::ProcessCreateEvent {
            process: Some(v1::ProcessInfo {
                pid,
                parent_pid,
                name: image_name,
                path: image_path,
                command_line: String::new(),
                session_id: String::new(),
                integrity_level: String::new(),
                user_sid: String::new(),
                user_name: String::new(),
                hashes: None,
                signature: None,
                start_time: None,
            }),
            parent_name: String::new(),
            parent_path: String::new(),
            parent_command_line: String::new(),
            parent_hashes: None,
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_process".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }
}

fn handle_process_stop(pid: u32, _data: &[u8], ctx: &EtwDispatchContext) {
    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let proto_event = v1::Event {
        id: Some(v1::Uuid {
            value: uuid::Uuid::new_v4().as_bytes().to_vec(),
        }),
        endpoint_id: None,
        event_type: v1::EventType::ProcessExit.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::ProcessExit(v1::ProcessExitEvent {
            pid,
            exit_code: 0,
            run_time_nanos: 0,
            exit_time: Some(ts),
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_process".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }
}

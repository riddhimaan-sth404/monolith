use chrono::Utc;
use prost_types::Timestamp;
use std::os::windows::ffi::OsStringExt;

use monolith_protobuf::proto::v1::{self, event::Payload};

use crate::etw_manager::EtwDispatchContext;

pub fn handle_event(event_id: u16, pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    let key_path = extract_key_path(data);
    if key_path.is_empty() {
        return;
    }

    let operation = match event_id {
        1 => 1, // RegOpCreateKey
        2 => 3, // RegOpSetValue
        3 => 2, // RegOpDeleteKey
        4 => 4, // RegOpDeleteValue
        5 => 5, // RegOpRenameKey
        _ => return,
    };

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
        event_type: v1::EventType::RegistryChange.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::RegistryChange(v1::RegistryChangeEvent {
            key_path,
            value_name: String::new(),
            old_value: String::new(),
            new_value: String::new(),
            pid,
            process_name: String::new(),
            operation,
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_registry".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }
}

fn extract_key_path(data: &[u8]) -> String {
    if data.len() < 8 {
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
        if chars.len() > 1024 {
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

    fn make_registry_buf(key_path: &str) -> Vec<u8> {
        let encoded: Vec<u16> = key_path.encode_utf16().collect();
        let total = 8 + 2 + encoded.len() * 2;
        let total = if total % 2 == 0 { total } else { total + 1 };
        let mut buf = vec![0u8; total];
        for (i, &cp) in encoded.iter().enumerate() {
            let off = 8 + 2 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        buf
    }

    #[test]
    fn test_extract_key_path_empty() {
        assert_eq!(extract_key_path(&[]), "");
    }

    #[test]
    fn test_extract_key_path_short() {
        assert_eq!(extract_key_path(&[0u8; 4]), "");
    }

    #[test]
    fn test_extract_key_path_valid() {
        let buf = make_registry_buf("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        let result = extract_key_path(&buf);
        assert_eq!(
            result,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        );
    }

    #[test]
    fn test_extract_key_path_long_truncated() {
        let long = format!("HKLM\\{}", "k".repeat(1100));
        let buf = make_registry_buf(&long);
        assert!(extract_key_path(&buf).len() <= 1025);
    }

    #[test]
    fn test_handle_registry_create() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\Test");
        handle_event(1, 1001, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::RegistryChange as i32);
        if let Some(Payload::RegistryChange(ref r)) = ev.payload {
            assert_eq!(r.key_path, "HKLM\\SOFTWARE\\Test");
            assert_eq!(r.operation, 1);
            assert_eq!(r.pid, 1001);
        } else {
            panic!("expected RegistryChange payload");
        }
    }

    #[test]
    fn test_handle_registry_set_value() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\Test\\Value");
        handle_event(2, 1002, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::RegistryChange(ref r)) = ev.payload {
            assert_eq!(r.operation, 3);
        }
    }

    #[test]
    fn test_handle_registry_delete_key() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\DeleteMe");
        handle_event(3, 1003, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::RegistryChange(ref r)) = ev.payload {
            assert_eq!(r.operation, 2);
        }
    }

    #[test]
    fn test_handle_registry_delete_value() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\DelValue");
        handle_event(4, 1004, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::RegistryChange(ref r)) = ev.payload {
            assert_eq!(r.operation, 4);
        }
    }

    #[test]
    fn test_handle_registry_rename() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\RenameMe");
        handle_event(5, 1005, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::RegistryChange(ref r)) = ev.payload {
            assert_eq!(r.operation, 5);
        }
    }

    #[test]
    fn test_handle_registry_unknown_event_id() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_registry_buf("HKLM\\SOFTWARE\\Noop");
        handle_event(99, 1006, &buf, &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }

    #[test]
    fn test_handle_registry_empty_path_no_emit() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(1, 1007, &[0u8; 4], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }
}

use std::collections::HashMap;
use std::os::windows::ffi::OsStringExt;
use std::sync::Mutex as StdMutex;
use std::time::Instant;
use chrono::Utc;
use prost_types::Timestamp;

use monolith_protobuf::proto::v1::{self, event::Payload};

use crate::etw_manager::EtwDispatchContext;

static RATE_LIMIT: std::sync::LazyLock<StdMutex<HashMap<String, Instant>>> =
    std::sync::LazyLock::new(|| StdMutex::new(HashMap::new()));

pub fn handle_event(event_id: u16, pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    let operation = match event_id {
        1 | 9 => v1::file_event::FileOperation::FileOpCreate,
        5 => v1::file_event::FileOperation::FileOpWrite,
        6 => v1::file_event::FileOperation::FileOpDelete,
        7 | 8 => v1::file_event::FileOperation::FileOpRename,
        _ => return,
    };

    let file_path = parse_file_path(data);
    if file_path.is_empty() {
        return;
    }

    // Rate limit: at most 1 event per path per second
    {
        let mut rl = RATE_LIMIT.lock().unwrap();
        if let Some(last) = rl.get(&file_path) {
            if last.elapsed() < std::time::Duration::from_secs(1) {
                return;
            }
        }
        rl.insert(file_path.clone(), Instant::now());
    }

    let file_name = file_path.rsplit('\\').next().unwrap_or(&file_path).to_string();
    let extension = std::path::Path::new(&file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let event_type = match operation {
        v1::file_event::FileOperation::FileOpCreate => v1::EventType::FileCreate,
        v1::file_event::FileOperation::FileOpWrite => v1::EventType::FileModify,
        v1::file_event::FileOperation::FileOpDelete => v1::EventType::FileDelete,
        v1::file_event::FileOperation::FileOpRename => v1::EventType::FileRename,
        _ => v1::EventType::Unspecified,
    };

    let proto_event = v1::Event {
        id: Some(v1::Uuid { value: uuid::Uuid::new_v4().as_bytes().to_vec() }),
        endpoint_id: None,
        event_type: event_type.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::FileEvent(v1::FileEvent {
            path: file_path.clone(),
            name: file_name,
            extension,
            size: 0,
            hashes: None,
            pid,
            process_name: String::new(),
            operation: operation.into(),
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_file".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }

    if matches!(operation, v1::file_event::FileOperation::FileOpCreate | v1::file_event::FileOperation::FileOpWrite) {
        let scan_url = ctx.scan_url.clone();
        let client = ctx.http_client.clone();
        let path = file_path.clone();
        std::thread::spawn(move || {
            let body = serde_json::json!({"path": path});
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                let _ = rt.block_on(async {
                    let _ = client.post(&format!("{}/api/scan/file", scan_url))
                        .json(&body).send().await;
                });
            }
        });
    }
}

fn parse_file_path(data: &[u8]) -> String {
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
        if code == 0 { break; }
        chars.push(code);
        i -= 2;
        if chars.len() > 260 { break; }
    }
    chars.reverse();
    if chars.is_empty() { return String::new(); }
    <std::ffi::OsString as OsStringExt>::from_wide(&chars).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_utf16_payload(s: &str, pad_bytes: usize) -> Vec<u8> {
        let encoded: Vec<u16> = s.encode_utf16().collect();
        let total = pad_bytes + 2 + encoded.len() * 2;
        let total = if total % 2 == 0 { total } else { total + 1 };
        let mut buf = vec![0u8; total];
        for (i, &cp) in encoded.iter().enumerate() {
            let off = pad_bytes + 2 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        buf
    }

    #[test]
    fn test_parse_file_path_empty_data() {
        assert_eq!(parse_file_path(&[]), "");
    }

    #[test]
    fn test_parse_file_path_less_than_8_bytes() {
        assert_eq!(parse_file_path(&[0u8; 4]), "");
    }

    #[test]
    fn test_parse_file_path_valid() {
        let buf = make_utf16_payload("C:\\Users\\test\\file.txt", 16);
        assert_eq!(parse_file_path(&buf), "C:\\Users\\test\\file.txt");
    }

    #[test]
    fn test_parse_file_path_odd_length_data() {
        let mut buf = make_utf16_payload("C:\\test.exe", 10);
        buf.push(0xff); // make it odd
        assert_eq!(parse_file_path(&buf), "C:\\test.exe");
    }

    #[test]
    fn test_parse_file_path_long_truncated() {
        let long = format!("C:\\{}.txt", "a".repeat(300));
        let buf = make_utf16_payload(&long, 8);
        let result = parse_file_path(&buf);
        assert!(result.len() <= 261, "expected <= 261, got {}", result.len());
    }

    #[test]
    fn test_parse_file_path_no_null_before_data() {
        let encoded: Vec<u16> = "test.txt".encode_utf16().collect();
        let mut buf = vec![0xFFu8; 20 + 2 + encoded.len() * 2]; // extra 2 for null
        buf[20] = 0x00;
        buf[21] = 0x00;
        for (i, &cp) in encoded.iter().enumerate() {
            let off = 22 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        assert_eq!(parse_file_path(&buf), "test.txt");
    }

    #[test]
    fn test_handle_event_noop_for_unknown_event_id() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer,
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        handle_event(99, 1234, &[0u8; 10], &ctx);
        // buffer should still be empty (no event pushed)
    }

    #[test]
    fn test_handle_event_create_with_valid_path() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_utf16_payload("C:\\new.txt", 16);
        handle_event(1, 999, &buf, &ctx);
        let events = buffer.blocking_lock();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, v1::EventType::FileCreate as i32);
        if let Some(Payload::FileEvent(ref f)) = ev.payload {
            assert_eq!(f.path, "C:\\new.txt");
            assert_eq!(f.pid, 999);
        } else {
            panic!("expected FileEvent payload");
        }
    }

    #[test]
    fn test_handle_event_write() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_utf16_payload("C:\\data.bin", 16);
        handle_event(5, 100, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::FileModify as i32);
    }

    #[test]
    fn test_handle_event_delete() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_utf16_payload("C:\\old.log", 16);
        handle_event(6, 200, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::FileDelete as i32);
    }

    #[test]
    fn test_handle_event_rename() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_utf16_payload("C:\\moved.txt", 16);
        handle_event(7, 300, &buf, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::FileRename as i32);
    }

    #[test]
    fn test_handle_event_empty_path_no_emit() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        handle_event(1, 400, &[0u8; 10], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }

    #[test]
    fn test_rate_limit_same_path_within_one_second() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: "http://localhost:50053".to_string(),
            http_client: reqwest::Client::new(),
        };
        let buf = make_utf16_payload("C:\\frequent.txt", 16);
        handle_event(1, 500, &buf, &ctx);
        handle_event(1, 500, &buf, &ctx);
        assert_eq!(buffer.blocking_lock().len(), 1);
        RATE_LIMIT.lock().unwrap().clear();
    }
}

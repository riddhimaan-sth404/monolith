use chrono::Utc;
use prost_types::Timestamp;

use monolith_protobuf::proto::v1::{self, event::Payload, network_connect_event};

use crate::etw_manager::EtwDispatchContext;

pub fn handle_event(event_id: u16, pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    match event_id {
        1001 => handle_tcp_connect(pid, data, ctx),
        1003 => handle_tcp_disconnect(pid, data, ctx),
        1006 => handle_tcp_accept(pid, data, ctx),
        3006 => handle_dns_query(pid, data, ctx),
        _ => {}
    }
}

fn parse_ipv4(data: &[u8], offset: usize) -> String {
    if offset + 4 > data.len() {
        return String::new();
    }
    format!(
        "{}.{}.{}.{}",
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3]
    )
}

fn parse_port(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn push_network_event(
    pid: u32,
    local_addr: &str,
    local_port: u16,
    remote_addr: &str,
    remote_port: u16,
    protocol: &str,
    direction: i32,
    ctx: &EtwDispatchContext,
) {
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
        event_type: v1::EventType::NetworkConnect.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::NetworkConnect(v1::NetworkConnectEvent {
            pid,
            process_name: String::new(),
            local_address: local_addr.to_string(),
            local_port: local_port as u32,
            remote_address: remote_addr.to_string(),
            remote_port: remote_port as u32,
            protocol: protocol.to_string(),
            direction,
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_network".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }
}

fn push_dns_event(pid: u32, query: &str, ctx: &EtwDispatchContext) {
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
        event_type: v1::EventType::DnsQuery.into(),
        timestamp: Some(ts.clone()),
        collected_at: Some(ts),
        sequence_number: 0,
        payload: Some(Payload::DnsQuery(v1::DnsQueryEvent {
            pid,
            process_name: String::new(),
            query: query.to_string(),
            answers: vec![],
            query_type: "A".to_string(),
            response_code: 0,
        })),
        metadata: vec![v1::MetadataEntry {
            key: "source".to_string(),
            value: "etw_network".to_string(),
        }],
    };

    if let Ok(mut buf) = ctx.buffer.try_lock() {
        if buf.len() < 10000 {
            buf.push_back(proto_event);
        }
    }
}

fn handle_tcp_connect(pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    if data.len() < 12 {
        return;
    }
    let local = parse_ipv4(data, 0);
    let remote = parse_ipv4(data, 4);
    let lport = parse_port(data, 8);
    let rport = parse_port(data, 10);
    push_network_event(
        pid,
        &local,
        lport,
        &remote,
        rport,
        "TCP",
        network_connect_event::Direction::Outbound as i32,
        ctx,
    );
}

fn handle_tcp_disconnect(pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    if data.len() < 12 {
        return;
    }
    let local = parse_ipv4(data, 0);
    let remote = parse_ipv4(data, 4);
    let lport = parse_port(data, 8);
    let rport = parse_port(data, 10);
    push_network_event(
        pid,
        &local,
        lport,
        &remote,
        rport,
        "TCP",
        network_connect_event::Direction::Outbound as i32,
        ctx,
    );
}

fn handle_tcp_accept(pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    if data.len() < 12 {
        return;
    }
    let local = parse_ipv4(data, 0);
    let remote = parse_ipv4(data, 4);
    let lport = parse_port(data, 8);
    let rport = parse_port(data, 10);
    push_network_event(
        pid,
        &local,
        lport,
        &remote,
        rport,
        "TCP",
        network_connect_event::Direction::Inbound as i32,
        ctx,
    );
}

fn handle_dns_query(pid: u32, data: &[u8], ctx: &EtwDispatchContext) {
    if data.len() < 8 {
        return;
    }
    let start = data.len() - (data.len() % 2);
    if start < 2 {
        return;
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
        if chars.len() > 256 {
            break;
        }
    }
    chars.reverse();
    if chars.is_empty() {
        return;
    }
    let query = <std::ffi::OsString as std::os::windows::ffi::OsStringExt>::from_wide(&chars);
    push_dns_event(pid, &query.to_string_lossy(), ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_utf16_payload(s: &str, header_bytes: usize) -> Vec<u8> {
        let encoded: Vec<u16> = s.encode_utf16().collect();
        let total = header_bytes + 2 + encoded.len() * 2;
        let total = if total % 2 == 0 { total } else { total + 1 };
        let mut buf = vec![0u8; total];
        for (i, &cp) in encoded.iter().enumerate() {
            let off = header_bytes + 2 + i * 2;
            buf[off] = cp as u8;
            buf[off + 1] = (cp >> 8) as u8;
        }
        buf
    }

    // --- parse_ipv4 ---

    #[test]
    fn test_parse_ipv4_valid() {
        let data = [192u8, 168, 1, 1, 10, 0, 0, 1];
        assert_eq!(parse_ipv4(&data, 0), "192.168.1.1");
        assert_eq!(parse_ipv4(&data, 4), "10.0.0.1");
    }

    #[test]
    fn test_parse_ipv4_offset_out_of_bounds() {
        assert_eq!(parse_ipv4(&[1u8, 2, 3], 0), "");
    }

    #[test]
    fn test_parse_ipv4_partial() {
        assert_eq!(parse_ipv4(&[192u8, 168, 1], 0), "");
    }

    // --- parse_port ---

    #[test]
    fn test_parse_port_valid() {
        // 443 in big endian
        let data = [0x01u8, 0xBB, 0x00, 0x50];
        assert_eq!(parse_port(&data, 0), 443);
        assert_eq!(parse_port(&data, 2), 80);
    }

    #[test]
    fn test_parse_port_offset_out_of_bounds() {
        assert_eq!(parse_port(&[0x00, 0x50], 3), 0);
    }

    #[test]
    fn test_parse_port_zero() {
        let data = [0x00u8, 0x00];
        assert_eq!(parse_port(&data, 0), 0);
    }

    // --- TCP connect ---

    #[test]
    fn test_tcp_connect_pushes_outbound() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        // local=10.0.0.5:4000, remote=93.184.216.34:80
        let mut data = vec![10u8, 0, 0, 5, 93, 184, 216, 34, 0x0F, 0xA0, 0x00, 0x50];
        data.resize(12, 0);
        handle_event(1001, 2001, &data, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::NetworkConnect as i32);
        if let Some(Payload::NetworkConnect(ref n)) = ev.payload {
            assert_eq!(n.local_address, "10.0.0.5");
            assert_eq!(n.local_port, 4000);
            assert_eq!(n.remote_address, "93.184.216.34");
            assert_eq!(n.remote_port, 80);
            assert_eq!(n.protocol, "TCP");
            assert_eq!(
                n.direction,
                network_connect_event::Direction::Outbound as i32
            );
            assert_eq!(n.pid, 2001);
        } else {
            panic!("expected NetworkConnect payload");
        }
    }

    #[test]
    fn test_tcp_connect_short_data() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(1001, 2002, &[0u8; 10], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }

    // --- TCP disconnect ---

    #[test]
    fn test_tcp_disconnect_pushes_outbound() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let mut data = vec![10u8, 0, 0, 1, 8, 8, 8, 8, 0x1F, 0x90, 0x00, 0x35];
        data.resize(12, 0);
        handle_event(1003, 3001, &data, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::NetworkConnect as i32);
        if let Some(Payload::NetworkConnect(ref n)) = ev.payload {
            assert_eq!(n.local_address, "10.0.0.1");
            assert_eq!(n.local_port, 8080);
            assert_eq!(n.remote_address, "8.8.8.8");
            assert_eq!(n.remote_port, 53);
            assert_eq!(
                n.direction,
                network_connect_event::Direction::Outbound as i32
            );
        }
    }

    // --- TCP accept ---

    #[test]
    fn test_tcp_accept_pushes_inbound() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let mut data = vec![192u8, 168, 1, 100, 10, 0, 0, 50, 0x00, 0x50, 0x0A, 0x28];
        data.resize(12, 0);
        handle_event(1006, 4001, &data, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::NetworkConnect(ref n)) = ev.payload {
            assert_eq!(n.local_address, "192.168.1.100");
            assert_eq!(n.local_port, 80);
            assert_eq!(n.remote_address, "10.0.0.50");
            assert_eq!(n.remote_port, 2600);
            assert_eq!(
                n.direction,
                network_connect_event::Direction::Inbound as i32
            );
            assert_eq!(n.protocol, "TCP");
        }
    }

    // --- DNS query ---

    #[test]
    fn test_dns_query_pushes_event() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let data = make_utf16_payload("evil.example.com", 8);
        handle_event(3006, 5001, &data, &ctx);
        let ev = &buffer.blocking_lock()[0];
        assert_eq!(ev.event_type, v1::EventType::DnsQuery as i32);
        if let Some(Payload::DnsQuery(ref d)) = ev.payload {
            assert_eq!(d.query, "evil.example.com");
            assert_eq!(d.pid, 5001);
        } else {
            panic!("expected DnsQuery payload");
        }
    }

    #[test]
    fn test_dns_query_short_data() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(3006, 5002, &[0u8; 4], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }

    #[test]
    fn test_dns_query_long_truncated() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        let long = format!("{}.com", "a".repeat(300));
        let data = make_utf16_payload(&long, 8);
        handle_event(3006, 5003, &data, &ctx);
        let ev = &buffer.blocking_lock()[0];
        if let Some(Payload::DnsQuery(ref d)) = ev.payload {
            assert!(
                d.query.len() <= 257,
                "expected <= 257, got {}",
                d.query.len()
            );
        }
    }

    // --- Unknown event ---

    #[test]
    fn test_unknown_event_id_noop() {
        let buffer = Arc::new(Mutex::new(VecDeque::new()));
        let ctx = EtwDispatchContext {
            buffer: buffer.clone(),
            scan_url: String::new(),
            http_client: reqwest::Client::new(),
        };
        handle_event(9999, 6001, &[0u8; 12], &ctx);
        assert!(buffer.blocking_lock().is_empty());
    }
}

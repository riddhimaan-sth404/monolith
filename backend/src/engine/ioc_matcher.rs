use serde_json::Value;
use dashmap::DashSet;

pub struct IocMatcher {
    sha256_set: DashSet<String>,
    sha1_set: DashSet<String>,
    md5_set: DashSet<String>,
    domain_set: DashSet<String>,
    ip_set: DashSet<String>,
}

impl IocMatcher {
    pub fn new() -> Self {
        Self {
            sha256_set: DashSet::new(),
            sha1_set: DashSet::new(),
            md5_set: DashSet::new(),
            domain_set: DashSet::new(),
            ip_set: DashSet::new(),
        }
    }

    pub fn load_iocs(&self, iocs: &[Value]) {
        for ioc in iocs {
            let ioc_type = ioc.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("");
            let value = ioc.get("value").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

            match ioc_type {
                "sha256" => { self.sha256_set.insert(value); }
                "sha1" => { self.sha1_set.insert(value); }
                "md5" => { self.md5_set.insert(value); }
                "domain" => { self.domain_set.insert(value); }
                "ip" => { self.ip_set.insert(value); }
                _ => {}
            }
        }
    }

    pub fn match_event(&self, event: &Value) -> Option<Vec<super::detection::DetectionResult>> {
        let mut results = Vec::new();

        // Check file hashes
        if let Some(data) = event.get("data").and_then(|v| v.as_object()) {
            // SHA256 matching
            if let Some(sha256) = data.get("sha256").and_then(|v| v.as_str()) {
                if self.sha256_set.contains(&sha256.to_lowercase()) {
                    results.push(self.create_result("ioc_match", format!("SHA256 IOC match: {}", sha256)));
                }
            }

            // SHA1 matching
            if let Some(sha1) = data.get("sha1").and_then(|v| v.as_str()) {
                if self.sha1_set.contains(&sha1.to_lowercase()) {
                    results.push(self.create_result("ioc_match", format!("SHA1 IOC match: {}", sha1)));
                }
            }

            // MD5 matching
            if let Some(md5) = data.get("md5").and_then(|v| v.as_str()) {
                if self.md5_set.contains(&md5.to_lowercase()) {
                    results.push(self.create_result("ioc_match", format!("MD5 IOC match: {}", md5)));
                }
            }

            // Domain matching (network events)
            if let Some(domain) = data.get("domain").and_then(|v| v.as_str()) {
                if self.domain_set.contains(&domain.to_lowercase()) {
                    results.push(self.create_result("ioc_match", format!("Domain IOC match: {}", domain)));
                }
            }

            // IP matching
            if let Some(ip) = data.get("remote_address").and_then(|v| v.as_str()) {
                if self.ip_set.contains(&ip.to_lowercase()) {
                    results.push(self.create_result("ioc_match", format!("IP IOC match: {}", ip)));
                }
            }
        }

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    fn create_result(&self, rule_type: &str, description: String) -> super::detection::DetectionResult {
        super::detection::DetectionResult {
            rule_id: format!("{}_{}", rule_type, uuid::Uuid::new_v4()),
            rule_name: format!("IOC: {}", description),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            mitre_technique_id: None,
            tags: vec!["ioc".to_string(), rule_type.to_string()],
            score: 8.0,
            matched_fields: std::collections::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ioc(ioc_type: &str, value: &str) -> Value {
        serde_json::json!({
            "ioc_type": ioc_type,
            "value": value,
        })
    }

    #[test]
    fn test_match_sha256() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("sha256", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")]);

        let event = serde_json::json!({
            "event_type": "process_create",
            "data": {
                "sha256": "ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_some());
        assert_eq!(results.unwrap().len(), 1);
    }

    #[test]
    fn test_match_sha1() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("sha1", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")]);

        let event = serde_json::json!({
            "event_type": "process_create",
            "data": {
                "sha1": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_some());
    }

    #[test]
    fn test_match_md5() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("md5", "d41d8cd98f00b204e9800998ecf8427e")]);

        let event = serde_json::json!({
            "event_type": "process_create",
            "data": {
                "md5": "D41D8CD98F00B204E9800998ECF8427E",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_some());
    }

    #[test]
    fn test_match_domain() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("domain", "evil.example.com")]);

        let event = serde_json::json!({
            "event_type": "network_connect",
            "data": {
                "domain": "Evil.Example.COM",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_some());
    }

    #[test]
    fn test_match_ip() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("ip", "185.220.101.1")]);

        let event = serde_json::json!({
            "event_type": "network_connect",
            "data": {
                "remote_address": "185.220.101.1",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_some());
    }

    #[test]
    fn test_no_match() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("sha256", "0000000000000000000000000000000000000000000000000000000000000000")]);

        let event = serde_json::json!({
            "event_type": "process_create",
            "data": {
                "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            }
        });

        let results = matcher.match_event(&event);
        assert!(results.is_none());
    }

    #[test]
    fn test_load_multiple_iocs() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[
            make_ioc("sha256", "aaaa"),
            make_ioc("sha256", "bbbb"),
            make_ioc("domain", "test.com"),
            make_ioc("ip", "1.2.3.4"),
            make_ioc("sha1", "cccc"),
            make_ioc("md5", "dddd"),
        ]);

        assert_eq!(matcher.sha256_set.len(), 2);
        assert_eq!(matcher.domain_set.len(), 1);
        assert_eq!(matcher.ip_set.len(), 1);
        assert_eq!(matcher.sha1_set.len(), 1);
        assert_eq!(matcher.md5_set.len(), 1);
    }

    #[test]
    fn test_unknown_ioc_type_ignored() {
        let matcher = IocMatcher::new();
        matcher.load_iocs(&[make_ioc("unknown_type", "value")]);
        assert!(matcher.sha256_set.is_empty());
    }
}

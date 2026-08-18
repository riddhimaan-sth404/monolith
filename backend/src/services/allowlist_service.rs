use crate::db::repos::AllowlistRepository;
use monolith_shared::db::traits::{DatabaseConnection, Repository};
use monolith_shared::error::Result;

pub struct AllowlistService {
    repo: AllowlistRepository,
}

impl Default for AllowlistService {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowlistService {
    pub fn new() -> Self {
        Self {
            repo: AllowlistRepository,
        }
    }

    pub async fn is_event_allowed(&self, _event_type: &str, data: &serde_json::Value, conn: &dyn DatabaseConnection) -> Result<bool> {
        let rules = self.repo.find_all(conn).await?;
        if rules.is_empty() {
            return Ok(false);
        }

        let sha256 = data.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let md5 = data.get("md5").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let path = data.get("path").or_else(|| data.get("image_path")).and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let cmd = data.get("command_line").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

        for rule in rules {
            let rule_type = rule.get("rule_type").and_then(|v| v.as_str()).unwrap_or("");
            let val = rule.get("value").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

            match rule_type {
                "hash_sha256" => {
                    if !sha256.is_empty() && sha256 == val {
                        return Ok(true);
                    }
                }
                "hash_md5" => {
                    if !md5.is_empty() && md5 == val {
                        return Ok(true);
                    }
                }
                "process_path" => {
                    if !path.is_empty() && path == val {
                        return Ok(true);
                    }
                }
                "cmdline_pattern" => {
                    if !cmd.is_empty() && cmd.contains(&val) {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        Ok(false)
    }
}

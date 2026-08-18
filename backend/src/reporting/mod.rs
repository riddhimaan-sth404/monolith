use printpdf::*;
use serde_json::Value;
use std::io::BufWriter;
use monolith_shared::error::{EdrError, Result};

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_pdf(&self, data: &Value, _output_path: &str) -> Result<Vec<u8>> {
        let (doc, page1, layer1) = PdfDocument::new(
            "EDR Report",
            Mm(210.0),
            Mm(297.0),
            "Layer 1",
        );

        let font = doc.add_builtin_font(BuiltinFont::Helvetica)
            .map_err(|e| EdrError::Internal(format!("PDF font error: {}", e)))?;
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)
            .map_err(|e| EdrError::Internal(format!("PDF font bold error: {}", e)))?;

        let current_layer = doc.get_page(page1).get_layer(layer1);

        // Title
        let title = data.get("title").and_then(|v| v.as_str()).unwrap_or("EDR Report");
        current_layer.use_text(title, 24.0, Mm(20.0), Mm(270.0), &font_bold);

        // Timestamp
        let timestamp = data.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        if !timestamp.is_empty() {
            current_layer.use_text(&format!("Generated: {}", timestamp), 10.0, Mm(20.0), Mm(260.0), &font);
        }

        // Summary section
        if let Some(summary) = data.get("summary") {
            current_layer.use_text("Summary", 16.0, Mm(20.0), Mm(245.0), &font_bold);

            let mut y_pos = 235.0_f32;
            if let Some(obj) = summary.as_object() {
                for (key, val) in obj {
                    let line = format!("{}: {}", key, val);
                    current_layer.use_text(&line, 10.0, Mm(25.0), Mm(y_pos), &font);
                    y_pos -= 6.0;
                }
            }
        }

        // Alerts table header
        let mut y_pos = 200.0_f32;
        if let Some(alerts) = data.get("alerts").and_then(|v| v.as_array()) {
            current_layer.use_text("Alerts", 16.0, Mm(20.0), Mm(y_pos), &font_bold);
            y_pos -= 8.0;

            // Table header
            current_layer.use_text("Severity", 9.0, Mm(20.0), Mm(y_pos), &font_bold);
            current_layer.use_text("Title", 9.0, Mm(50.0), Mm(y_pos), &font_bold);
            current_layer.use_text("Status", 9.0, Mm(140.0), Mm(y_pos), &font_bold);
            current_layer.use_text("Score", 9.0, Mm(170.0), Mm(y_pos), &font_bold);
            y_pos -= 6.0;

            for alert in alerts.iter().take(50) {
                if y_pos < 20.0 {
                    break; // New page would be needed in production
                }

                let severity = alert.get("severity").and_then(|v| v.as_str()).unwrap_or("");
                let title = alert.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let status = alert.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let score = alert.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);

                let sev_font = if severity == "critical" || severity == "high" { &font_bold } else { &font };
                current_layer.use_text(severity, 8.0, Mm(20.0), Mm(y_pos), sev_font);
                current_layer.use_text(title, 8.0, Mm(50.0), Mm(y_pos), &font);
                current_layer.use_text(status, 8.0, Mm(140.0), Mm(y_pos), &font);
                current_layer.use_text(&format!("{:.1}", score), 8.0, Mm(170.0), Mm(y_pos), &font);

                y_pos -= 5.0;
            }
        }

        // Endpoints table
        if let Some(endpoints) = data.get("endpoints").and_then(|v| v.as_array()) {
            y_pos -= 10.0;
            current_layer.use_text("Endpoints", 16.0, Mm(20.0), Mm(y_pos), &font_bold);
            y_pos -= 8.0;

            for ep in endpoints.iter().take(30) {
                if y_pos < 20.0 {
                    break;
                }

                let hostname = ep.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
                let status = ep.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let ip = ep.get("ip_address").and_then(|v| v.as_str()).unwrap_or("");

                current_layer.use_text(hostname, 8.0, Mm(25.0), Mm(y_pos), &font);
                current_layer.use_text(status, 8.0, Mm(100.0), Mm(y_pos), &font);
                current_layer.use_text(ip, 8.0, Mm(140.0), Mm(y_pos), &font);

                y_pos -= 5.0;
            }
        }

        let mut writer = BufWriter::new(Vec::new());
        doc.save(&mut writer)
            .map_err(|e| EdrError::Internal(format!("PDF save error: {}", e)))?;
        let bytes = writer.into_inner()
            .map_err(|e| EdrError::Internal(format!("PDF buffer error: {}", e)))?;

        Ok(bytes)
    }

    pub fn generate_csv(&self, data: &[Value], fields: &[&str]) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        wtr.write_record(fields)
            .map_err(|e| EdrError::Internal(format!("CSV write error: {}", e)))?;

        for row in data {
            let values: Vec<String> = fields
                .iter()
                .map(|f| {
                    row.get(*f)
                        .map(|v| match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default()
                })
                .collect();
            wtr.write_record(&values)
                .map_err(|e| EdrError::Internal(format!("CSV write error: {}", e)))?;
        }

        let result = wtr.into_inner()
            .map_err(|e| EdrError::Internal(format!("CSV inner error: {}", e)))?;
        Ok(String::from_utf8(result)
            .map_err(|e| EdrError::Internal(format!("UTF-8 error: {}", e)))?)
    }

    pub fn generate_json(&self, data: &Value) -> Result<String> {
        Ok(serde_json::to_string_pretty(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_pdf_generation() {
        let generator = ReportGenerator::new();
        let data = json!({
            "title": "Test EDR Report",
            "timestamp": "2026-08-02T12:00:00Z",
            "summary": {
                "Total Scans": 10,
                "Threats Detected": 2
            },
            "alerts": [
                {
                    "severity": "critical",
                    "title": "Mimikatz LSASS Dump",
                    "status": "active",
                    "score": 9.5
                }
            ],
            "endpoints": [
                {
                    "hostname": "win-endpoint-1",
                    "status": "online",
                    "ip_address": "192.168.1.50"
                }
            ]
        });

        let pdf_bytes = generator.generate_pdf(&data, "dummy.pdf");
        assert!(pdf_bytes.is_ok());
        let bytes = pdf_bytes.unwrap();
        assert!(!bytes.is_empty());
        // Verify PDF magic header
        assert_eq!(&bytes[0..5], b"%PDF-");
    }

    #[test]
    fn test_csv_generation() {
        let generator = ReportGenerator::new();
        let data = vec![
            json!({
                "hostname": "win-1",
                "status": "online"
            })
        ];
        let fields = vec!["hostname", "status"];
        let csv = generator.generate_csv(&data, &fields);
        assert!(csv.is_ok());
        let csv_str = csv.unwrap();
        assert!(csv_str.contains("hostname,status"));
        assert!(csv_str.contains("win-1,online"));
    }
}



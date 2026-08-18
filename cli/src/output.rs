use colored::*;
use serde_json::Value;
use tabled::{builder::Builder, settings::Style};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "csv" => Self::Csv,
            _ => Self::Table,
        }
    }
}

pub fn print_table(headers: &[&str], rows: &[Vec<String>], format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            let mut builder = Builder::new();
            builder.push_record(headers.iter().map(|h| h.to_string()));
            for row in rows {
                builder.push_record(row.iter().map(|s| s.clone()));
            }
            let table = builder.build().with(Style::rounded()).to_string();
            println!("{}", table);
        }
        OutputFormat::Json => {
            let arr: Vec<serde_json::Map<String, Value>> = rows
                .iter()
                .map(|row| {
                    let mut m = serde_json::Map::new();
                    for (i, h) in headers.iter().enumerate() {
                        m.insert(
                            h.to_string(),
                            Value::String(row.get(i).cloned().unwrap_or_default()),
                        );
                    }
                    m
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            wtr.write_record(headers).ok();
            for row in rows {
                wtr.write_record(row.iter().map(|s| s.as_str())).ok();
            }
            wtr.flush().ok();
        }
    }
}

pub fn print_value(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

pub fn ok(msg: &str) {
    println!("{} {}", "[OK]".green(), msg);
}

#[allow(dead_code)]
pub fn err(msg: &str) {
    eprintln!("{} {}", "[ERR]".red(), msg);
}

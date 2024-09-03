use std::env;
use log::LevelFilter;

#[derive(Clone)]
pub struct Config {
    pub log_level: LevelFilter,
}

impl Config {
    pub fn new() -> Self {
        let log_level = match env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()).to_lowercase().as_str() {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Info,
        };

        Config { log_level }
    }
}
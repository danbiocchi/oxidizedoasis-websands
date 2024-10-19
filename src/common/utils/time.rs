use chrono::{DateTime, Duration, Utc};

pub fn is_expired(timestamp: &DateTime<Utc>) -> bool {
    Utc::now() > *timestamp
}

pub fn add_hours(hours: i64) -> DateTime<Utc> {
    Utc::now() + Duration::hours(hours)
}

pub fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
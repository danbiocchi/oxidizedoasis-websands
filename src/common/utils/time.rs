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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn test_is_expired_past_timestamp() {
        let past_time = Utc::now() - Duration::seconds(10);
        assert!(is_expired(&past_time));
    }

    #[test]
    fn test_is_expired_future_timestamp() {
        let future_time = Utc::now() + Duration::seconds(10);
        assert!(!is_expired(&future_time));
    }

    #[test]
    fn test_is_expired_now_timestamp() {
        // This test can be a bit flaky due to execution time.
        // A timestamp created just before the check might be considered expired or not.
        // For robustness, we might consider a small epsilon, but the current logic is strict.
        let now_time = Utc::now();
        // It's possible Utc::now() in is_expired is slightly later, making now_time appear expired.
        // Or it could be slightly earlier if the clock ticks between the two Utc::now() calls.
        // Let's test a point slightly in the future that should not be expired.
        let slightly_future = Utc::now() + Duration::milliseconds(100);
        assert!(!is_expired(&slightly_future));

        // And a point slightly in the past
        let slightly_past = Utc::now() - Duration::milliseconds(100);
        // Need a brief pause to ensure Utc::now() in is_expired is later
        std::thread::sleep(std::time::Duration::from_millis(1)); 
        assert!(is_expired(&slightly_past));
    }

    #[test]
    fn test_add_hours_positive() {
        let hours_to_add = 5;
        let expected_time_approx = Utc::now() + Duration::hours(hours_to_add);
        let actual_time = add_hours(hours_to_add);
        // Allow a small delta for the time difference between Utc::now() calls
        let delta = (expected_time_approx - actual_time).num_seconds().abs();
        assert!(delta <= 1, "Times should be very close. Delta: {}s", delta);
    }

    #[test]
    fn test_add_hours_negative() {
        let hours_to_add = -3;
        let expected_time_approx = Utc::now() + Duration::hours(hours_to_add);
        let actual_time = add_hours(hours_to_add);
        let delta = (expected_time_approx - actual_time).num_seconds().abs();
        assert!(delta <= 1, "Times should be very close. Delta: {}s", delta);
    }

    #[test]
    fn test_add_hours_zero() {
        let hours_to_add = 0;
        let expected_time_approx = Utc::now() + Duration::hours(hours_to_add);
        let actual_time = add_hours(hours_to_add);
        let delta = (expected_time_approx - actual_time).num_seconds().abs();
        assert!(delta <= 1, "Times should be very close. Delta: {}s", delta);
    }

    #[test]
    fn test_format_timestamp_specific_date() {
        let specific_time = Utc.with_ymd_and_hms(2023, 10, 26, 14, 30, 5).unwrap();
        let formatted_string = format_timestamp(specific_time);
        assert_eq!(formatted_string, "2023-10-26 14:30:05 UTC");
    }

    #[test]
    fn test_format_timestamp_midnight() {
        let midnight_time = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let formatted_string = format_timestamp(midnight_time);
        assert_eq!(formatted_string, "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_noon() {
        let noon_time = Utc.with_ymd_and_hms(2024, 7, 15, 12, 0, 0).unwrap();
        let formatted_string = format_timestamp(noon_time);
        assert_eq!(formatted_string, "2024-07-15 12:00:00 UTC");
    }
}

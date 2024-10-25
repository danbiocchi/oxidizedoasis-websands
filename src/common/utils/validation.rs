use validator::ValidationError;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();

    pub static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();

    static ref PASSWORD_REGEX: Regex = Regex::new(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    ).unwrap();
}

pub fn validate_length(value: &str, min: usize, max: usize) -> Result<(), ValidationError> {
    if value.len() < min || value.len() > max {
        // Use to_owned to convert the formatted string to an owned String
        return Err(ValidationError {
            code: "length".into(),
            message: Some(format!("Length must be between {} and {} characters", min, max).to_owned().into()),
            params: Default::default(),
        });
    }
    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if !EMAIL_REGEX.is_match(email) {
        return Err(ValidationError::new("Invalid email format"));
    }
    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if !USERNAME_REGEX.is_match(username) {
        return Err(ValidationError::new(
            "Username must be 3-50 characters long and contain only letters, numbers, underscores, and hyphens"
        ));
    }
    Ok(())
}

pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    if !PASSWORD_REGEX.is_match(password) {
        return Err(ValidationError::new(
            "Password must be at least 8 characters long and contain at least one uppercase letter, \
             one lowercase letter, one number, and one special character"
        ));
    }
    Ok(())
}

pub fn sanitize_string(input: &str) -> String {
    ammonia::clean(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_length() {
        assert!(validate_length("test", 1, 10).is_ok());
        assert!(validate_length("test", 5, 10).is_err());
        assert!(validate_length("test", 1, 3).is_err());
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        assert!(validate_email("invalid.email").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("ab").is_err()); // Too short
        assert!(validate_username("user name").is_err()); // Contains space
        assert!(validate_username("user@name").is_err()); // Contains special char
    }

    #[test]
    fn test_validate_password_strength() {
        assert!(validate_password_strength("Password1!").is_ok());
        assert!(validate_password_strength("StrongP@ss1").is_ok());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("NoSpecial1").is_err());
        assert!(validate_password_strength("no_upper1!").is_err());
        assert!(validate_password_strength("NOLOWER1!").is_err());
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("<script>alert('xss')</script>"), "");
        assert_eq!(sanitize_string("Normal text"), "Normal text");
        assert_eq!(
            sanitize_string("<p>Safe <b>HTML</b></p>"),
            "<p>Safe <b>HTML</b></p>"
        );
    }
}

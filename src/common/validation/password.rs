use regex::Regex;
use validator::ValidationError;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref PASSWORD_UPPERCASE: Regex = Regex::new(r"[A-Z]").unwrap();
    pub static ref PASSWORD_LOWERCASE: Regex = Regex::new(r"[a-z]").unwrap();
    pub static ref PASSWORD_NUMBER: Regex = Regex::new(r"[0-9]").unwrap();
    pub static ref PASSWORD_SPECIAL: Regex = Regex::new(r#"[!@#$%^&*(),.?":{}|<>]"#).unwrap();
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 || password.len() > 100 {
        return Err(ValidationError::new("Password must be between 8 and 100 characters long"));
    }
    if !PASSWORD_UPPERCASE.is_match(password) {
        return Err(ValidationError::new("Password must contain at least one uppercase letter"));
    }
    if !PASSWORD_LOWERCASE.is_match(password) {
        return Err(ValidationError::new("Password must contain at least one lowercase letter"));
    }
    if !PASSWORD_NUMBER.is_match(password) {
        return Err(ValidationError::new("Password must contain at least one number"));
    }
    if !PASSWORD_SPECIAL.is_match(password) {
        return Err(ValidationError::new("Password must contain at least one special character"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::ValidationError;

    fn get_error_message(result: Result<(), ValidationError>) -> String {
        let error = result.err().expect("Expected an error to get a message from");
        // According to validator crate's ValidationError::new(code), 
        // message should be Some(Cow::Borrowed(code)).
        // However, if it were None, falling back to `code` is a robust way to get the error string.
        match error.message {
            Some(msg_cow) => msg_cow.into_owned(),
            None => error.code.into_owned(),
        }
    }

    #[test]
    fn test_valid_passwords() {
        assert!(validate_password("P@ssw0rd1").is_ok());
        assert!(validate_password("ValidPass!23").is_ok());
        assert!(validate_password("Another_Good_P@ssw0rd_789").is_ok());
        // Test with all allowed special characters
        assert!(validate_password("Test!@#$%^&*().?\":{}|<>P1").is_ok());
    }

    #[test]
    fn test_password_too_short() {
        let result = validate_password("Sh0rt!");
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must be between 8 and 100 characters long");
    }

    #[test]
    fn test_password_too_long() {
        let long_password = "a".repeat(101) + "B1!";
        let result = validate_password(&long_password);
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must be between 8 and 100 characters long");
    }

    #[test]
    fn test_password_missing_uppercase() {
        let result = validate_password("nouppercase!1");
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must contain at least one uppercase letter");
    }

    #[test]
    fn test_password_missing_lowercase() {
        let result = validate_password("NOLOWERCASE!1");
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must contain at least one lowercase letter");
    }

    #[test]
    fn test_password_missing_number() {
        let result = validate_password("NoNumberHere!");
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must contain at least one number");
    }

    #[test]
    fn test_password_missing_special_character() {
        let result = validate_password("NoSpecialChar1");
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must contain at least one special character");
    }
    
    #[test]
    fn test_password_empty() {
        let result = validate_password("");
        assert!(result.is_err());
        // It will fail length check first
        assert_eq!(get_error_message(result), "Password must be between 8 and 100 characters long");
    }

    #[test]
    fn test_password_just_under_min_length() {
        // 7 chars: "Val!d1"
        let result = validate_password("Val!d1A"); 
        assert!(result.is_err());
        assert_eq!(get_error_message(result), "Password must be between 8 and 100 characters long");
    }

    #[test]
    fn test_password_at_min_length() {
        assert!(validate_password("Val!d1Aa").is_ok()); // 8 chars
    }

    #[test]
    fn test_password_at_max_length() {
        let max_len_password = "a".repeat(90) + "B1!cDeFgH"; // 90 + 1 + 1 + 1 + 7 = 100
        assert!(validate_password(&max_len_password).is_ok());
    }

    #[test]
    fn test_password_just_over_max_length() {
        // Corrected: 94 'a's + "B1!cDeFgH" (7 chars) = 101 characters
        let over_max_len_password = "a".repeat(94) + "B1!cDeFgH"; 
        let result = validate_password(&over_max_len_password);
        assert!(result.is_err(), "Password with 101 chars should be an error. Got: {:?}", result);
        assert_eq!(get_error_message(result), "Password must be between 8 and 100 characters long");
    }
}

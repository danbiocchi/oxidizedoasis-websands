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

    #[test]
    fn test_password_validation() {
        assert!(validate_password("P@ssw0rd").is_ok());
        assert!(validate_password("L0ngP@ssw0rdWithManyCharacters").is_ok());

        assert!(validate_password("short").is_err());
        assert!(validate_password("lowercase").is_err());
        assert!(validate_password("UPPERCASE").is_err());
        assert!(validate_password("NoNumbers").is_err());
        assert!(validate_password("NoSpecial1").is_err());
        assert!(validate_password("").is_err());
        assert!(validate_password(&*"a".repeat(101)).is_err());
    }
}
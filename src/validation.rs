use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use lazy_static::lazy_static;

#[derive(Debug, Deserialize, Serialize, Validate, Clone)]
pub struct UserInput {
    #[validate(length(min = 3, max = 50), regex = "USERNAME_REGEX")]
    pub username: String,
    #[validate(email)]
    pub email: Option<String>,
    #[validate(custom = "validate_password")]
    pub password: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct LoginInput {
    #[validate(length(min = 3, max = 50), regex = "USERNAME_REGEX")]
    pub username: String,
    #[validate(custom = "validate_password")]
    pub password: String,
}


lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]{3,50}$").unwrap();
    static ref PASSWORD_UPPERCASE: Regex = Regex::new(r"[A-Z]").unwrap();
    static ref PASSWORD_LOWERCASE: Regex = Regex::new(r"[a-z]").unwrap();
    static ref PASSWORD_NUMBER: Regex = Regex::new(r"[0-9]").unwrap();
    static ref PASSWORD_SPECIAL: Regex = Regex::new(r#"[!@#$%^&*(),.?":{}|<>]"#).unwrap();
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
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

pub fn sanitize_input(input: &str) -> String {
    let stripped = ammonia::clean(input);
    stripped.trim().to_string()
}

pub fn validate_and_sanitize_user_input(input: UserInput) -> Result<UserInput, Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Validate username
    if let Err(e) = input.validate() {
        errors.extend(e.field_errors().values().cloned().flatten().cloned());
    }

    // Validate password if provided
    if let Some(ref password) = input.password {
        if let Err(e) = validate_password(password) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        Ok(UserInput {
            username: sanitize_input(&input.username),
            email: input.email.map(|e| sanitize_input(&e)),
            password: input.password,  // We don't sanitize passwords
        })
    } else {
        Err(errors)
    }
}

pub fn validate_and_sanitize_login_input(input: LoginInput) -> Result<LoginInput, Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Validate username
    if let Err(e) = input.validate() {
        errors.extend(e.field_errors().values().cloned().flatten().cloned());
    }

    // Validate password
    if let Err(e) = validate_password(&input.password) {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(LoginInput {
            username: sanitize_input(&input.username),
            password: input.password,  // We don't sanitize passwords
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_regex() {
        assert!(USERNAME_REGEX.is_match("user123"));
        assert!(USERNAME_REGEX.is_match("user_name"));
        assert!(USERNAME_REGEX.is_match("user-name"));
        assert!(USERNAME_REGEX.is_match(&*"a".repeat(50)));

        assert!(!USERNAME_REGEX.is_match("us"));
        assert!(!USERNAME_REGEX.is_match(&*"a".repeat(51)));
        assert!(!USERNAME_REGEX.is_match("user name"));
        assert!(!USERNAME_REGEX.is_match("user@name"));
        assert!(!USERNAME_REGEX.is_match(""));
    }

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
    #[test]
    fn test_sanitize_input() {
        assert_eq!(sanitize_input(" Hello, World! "), "Hello, World!");
        assert_eq!(sanitize_input("<script>alert('XSS')</script>"), "");
        assert_eq!(sanitize_input("<p>Safe <b>HTML</b></p>"), "<p>Safe <b>HTML</b></p>");
        assert_eq!(
            sanitize_input("<a href='javascript:alert(1)'>Link</a>"),
            "<a rel=\"noopener noreferrer\">Link</a>"
        );
    }

    #[test]
    fn test_validate_and_sanitize_user_input() {
        let valid_input = UserInput {
            username: "validuser".to_string(),
            email: Some("user@example.com".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(validate_and_sanitize_user_input(valid_input).is_ok());

        let invalid_username = UserInput {
            username: "in valid".to_string(),
            email: Some("user@example.com".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(validate_and_sanitize_user_input(invalid_username).is_err());

        let invalid_email = UserInput {
            username: "validuser".to_string(),
            email: Some("not_an_email".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(validate_and_sanitize_user_input(invalid_email).is_err());

        let invalid_password = UserInput {
            username: "validuser".to_string(),
            email: Some("user@example.com".to_string()),
            password: Some("weak".to_string()),
        };
        assert!(validate_and_sanitize_user_input(invalid_password).is_err());
    }

    #[test]
    fn test_validate_and_sanitize_login_input() {
        let valid_input = LoginInput {
            username: "validuser".to_string(),
            password: "V@lidP@ssw0rd".to_string(),
        };
        assert!(validate_and_sanitize_login_input(valid_input).is_ok());

        let invalid_username = LoginInput {
            username: "in valid".to_string(),
            password: "V@lidP@ssw0rd".to_string(),
        };
        assert!(validate_and_sanitize_login_input(invalid_username).is_err());

        let invalid_password = LoginInput {
            username: "validuser".to_string(),
            password: "weak".to_string(),
        };
        assert!(validate_and_sanitize_login_input(invalid_password).is_err());
    }

    #[test]
    fn test_user_input_struct_validation() {
        let valid_input = UserInput {
            username: "validuser".to_string(),
            email: Some("user@example.com".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(valid_input.validate().is_ok());

        let invalid_username = UserInput {
            username: "in valid".to_string(),
            email: Some("user@example.com".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(invalid_username.validate().is_err());

        let invalid_email = UserInput {
            username: "validuser".to_string(),
            email: Some("not_an_email".to_string()),
            password: Some("V@lidP@ssw0rd".to_string()),
        };
        assert!(invalid_email.validate().is_err());
    }

    #[test]
    fn test_login_input_struct_validation() {
        let valid_input = LoginInput {
            username: "validuser".to_string(),
            password: "V@lidP@ssw0rd".to_string(),
        };
        assert!(valid_input.validate().is_ok());

        let invalid_username = LoginInput {
            username: "in valid".to_string(),
            password: "V@lidP@ssw0rd".to_string(),
        };
        assert!(invalid_username.validate().is_err());

        let invalid_password = LoginInput {
            username: "validuser".to_string(),
            password: "weak".to_string(),
        };
        assert!(invalid_password.validate().is_err());
    }
}
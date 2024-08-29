use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use lazy_static::lazy_static;

#[derive(Debug, Deserialize, Serialize, Validate)]
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
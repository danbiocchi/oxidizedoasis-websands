use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use super::password::validate_password;

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
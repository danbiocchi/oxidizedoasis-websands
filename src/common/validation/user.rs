use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use super::password::validate_password;
use actix_web::web;
use super::super::utils::validation::USERNAME_REGEX;

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

#[derive(Debug, Deserialize, Serialize, Validate, Clone)]
// Removed struct-level: #[validate(custom = "validate_passwords_match")]
pub struct RegisterInput {
    #[validate(length(min = 3, max = 50))] // Temporarily removed regex
    pub username: String,
    #[validate(email)]
    pub email: String,
    // Temporarily removed custom password validation from derive
    // It will be handled in validate_and_sanitize_register_input
    pub password: String,
    // password_confirm itself doesn't need individual validation beyond being a string,
    // its comparison to 'password' is a struct-level concern.
    pub password_confirm: String,
}

// Struct-level validation function
fn validate_passwords_match(input: &RegisterInput) -> Result<(), ValidationError> {
    if input.password != input.password_confirm {
        // This error isn't tied to a specific field in the same way,
        // but we can make it behave like one for consistent error reporting.
        // Or, it can be a general struct error. For now, let's make it appear related to 'password_confirm'.
        let mut err = ValidationError::new("passwords_must_match"); // Changed error code
        err.message = Some("Passwords must match".into());
        // It's a common practice to associate such errors with one of the fields, e.g., password_confirm
        // However, the validator crate might handle struct-level errors differently in terms of field association.
        // For simplicity, we'll just return the error. The client can decide how to display it.
        // err.add_param("field".into(), "password_confirm".into()); // Optional: to hint which field
        return Err(err);
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

pub fn validate_and_sanitize_register_input(input: RegisterInput) -> Result<RegisterInput, Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Validate all fields using struct-level validation first
    if let Err(e) = input.validate() {
        errors.extend(e.field_errors().values().cloned().flatten().cloned());
    }
    
    // Manually call password validation since custom was removed from derive
    if let Err(e) = validate_password(&input.password) {
        errors.push(e);
    }

    // Manually call the password matching validation
    if let Err(e) = validate_passwords_match(&input) {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(RegisterInput {
            username: sanitize_input(&input.username),
            email: sanitize_input(&input.email),
            password: input.password, // We don't sanitize passwords
            password_confirm: input.password_confirm, // We don't sanitize passwords
        })
    } else {
        Err(errors)
    }
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct TokenQuery {
    #[validate(length(min = 1))]
    token: String,
}

impl TokenQuery {
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl TryFrom<web::Query<TokenQuery>> for TokenQuery {
    type Error = actix_web::Error;

    fn try_from(query: web::Query<TokenQuery>) -> Result<Self, Self::Error> {
        if let Err(e) = query.validate() {
            return Err(actix_web::error::ErrorBadRequest(e));
        }
        Ok(query.into_inner())
    }
}

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

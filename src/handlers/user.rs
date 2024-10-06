use actix_web::{web, HttpResponse, Responder, get, put, delete};
use sqlx::PgPool;
use crate::models::user::{User, UserResponse};
use crate::email::EmailServiceTrait;
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use log::{debug, error, info, warn};
use chrono::{Utc, Duration};
use crate::auth;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::Deserialize;
use std::convert::TryFrom;
use crate::validation::{UserInput, LoginInput, validate_and_sanitize_user_input, validate_and_sanitize_login_input, sanitize_input};
use std::sync::Arc;
use serde_json::json;

#[derive(Deserialize)]
pub struct TokenQuery {
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
        if !query.token.chars().all(|c| c.is_ascii_alphanumeric()) || query.token.len() != 32 {
            return Err(actix_web::error::ErrorBadRequest("Invalid token format"));
        }
        Ok(query.0)
    }
}

pub async fn create_user(
    pool: web::Data<PgPool>,
    user: web::Json<UserInput>,
    email_service: web::Data<Arc<dyn EmailServiceTrait>>,
) -> impl Responder {
    match validate_and_sanitize_user_input(user.into_inner()) {
        Ok(validated_user) => {
            debug!("Received create_user request at /users/register");
            info!("Attempting to create user: {:?}", validated_user);

            let password_hash = match validated_user.password {
                Some(password) => match hash(&password, DEFAULT_COST) {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!("Failed to hash password: {:?}", e);
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Internal server error",
                            "message": "Failed to create user"
                        }));
                    }
                },
                None => return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Bad request",
                    "message": "Password is required for user creation"
                })),
            };

            let verification_token = generate_verification_token();
            let verification_token_expires_at = Utc::now() + Duration::hours(24);
            let now = Utc::now();

            let result = sqlx::query_as!(
                User,
                r#"INSERT INTO users (id, username, email, password_hash, is_email_verified, verification_token, verification_token_expires_at, created_at, updated_at, role)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING *"#,
                Uuid::new_v4(),
                validated_user.username,
                validated_user.email,
                password_hash,
                false,
                verification_token,
                verification_token_expires_at,
                now,
                now,
                "user"
            )
                .fetch_one(pool.get_ref())
                .await;

            match result {
                Ok(user) => {
                    let email_service = email_service.get_ref();
                    match email_service.send_verification_email(user.email.as_deref().unwrap_or_default(), &verification_token) {
                        Ok(_) => {
                            info!("Verification email sent to: {}", user.email.as_deref().unwrap_or_default());
                            let user_response: UserResponse = user.into();
                            HttpResponse::Created().json(serde_json::json!({
                                "message": "User created successfully",
                                "email": user_response.email,
                                "user": user_response
                            }))
                        },
                        Err(e) => {
                            error!("Failed to send verification email: {:?}", e);
                            HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Internal server error",
                                "message": "User created but failed to send verification email"
                            }))
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to create user: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal server error",
                        "message": "Failed to create user"
                    }))
                }
            }
        },
        Err(errors) => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Bad request",
                "messages": errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>()
            }))
        }
    }
}

pub async fn login_user(pool: web::Data<PgPool>, user: web::Json<LoginInput>) -> impl Responder {
    let validated_user = match validate_and_sanitize_login_input(user.into_inner()) {
        Ok(user) => user,
        Err(errors) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Bad request",
            "messages": errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>()
        })),
    };

    let user_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        validated_user.username
    )
        .fetch_optional(pool.get_ref())
        .await;

    match user_result {
        Ok(Some(db_user)) => {
            if !db_user.is_email_verified {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Unauthorized",
                    "message": "Email has not been verified yet. Please check your email for the verification link.",
                    "error_type": "email_not_verified"
                }));
            }

            match verify(&validated_user.password, &db_user.password_hash) {
                Ok(true) => {
                    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                    match auth::create_jwt(db_user.id, &jwt_secret) {
                        Ok(token) => {
                            let user_response: UserResponse = db_user.into();
                            HttpResponse::Ok().json(serde_json::json!({
                                "message": "Login successful",
                                "token": token,
                                "user": user_response
                            }))
                        },
                        Err(e) => {
                            error!("Failed to create JWT: {:?}", e);
                            HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Internal server error",
                                "message": "Error during login"
                            }))
                        }
                    }
                },
                Ok(false) => HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Unauthorized",
                    "message": "Invalid username or password"
                })),
                Err(e) => {
                    error!("Error verifying password: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal server error",
                        "message": "Error verifying password"
                    }))
                },
            }
        },
        Ok(None) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid username or password"
        })),
        Err(e) => {
            error!("Database error during login: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error",
                "message": "Error logging in"
            }))
        }
    }
}

pub async fn verify_email(
    pool: web::Data<PgPool>,
    token_query: web::Query<TokenQuery>,
) -> Result<impl Responder, actix_web::Error> {
    let token = TokenQuery::try_from(token_query)?;
    let sanitized_token = sanitize_input(token.token());

    debug!("Received email verification request with token: {}", sanitized_token);

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET is_email_verified = TRUE, verification_token = NULL, verification_token_expires_at = NULL
        WHERE verification_token = $1 AND verification_token_expires_at > CURRENT_TIMESTAMP
        RETURNING id
        "#,
        sanitized_token
    )
        .fetch_optional(pool.get_ref())
        .await;

    match result {
        Ok(Some(_)) => {
            info!("Email verified successfully");
            Ok(HttpResponse::Found()
                .append_header((actix_web::http::header::LOCATION, "/email_verified"))
                .finish())
        },
        Ok(None) => {
            warn!("Invalid or expired verification token");
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid or expired token",
                "message": "The verification link is invalid or has expired. Please request a new verification email."
            })))
        },
        Err(e) => {
            error!("Failed to verify email: {:?}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error",
                "message": "An error occurred while verifying your email. Please try again later."
            })))
        }
    }
}
#[get("/users/{id}")]
pub async fn get_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    let user_id = id.into_inner();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) => {
            if claims.sub != user_id {
                warn!("Unauthorized access attempt: User {} tried to access data for user {}", claims.sub, user_id);
                return HttpResponse::Forbidden().json(json!({
                    "error": "Forbidden",
                    "message": "Access denied: You can only view your own information"
                }));
            }
            fetch_user_by_id(pool, user_id).await
        },
        Err(e) => {
            warn!("Invalid token used for authentication: {:?}", e);
            HttpResponse::Unauthorized().json(json!({
                "error": "Unauthorized",
                "message": "Invalid token"
            }))
        },
    }
}

#[get("/users/me")]
pub async fn get_current_user(
    pool: web::Data<PgPool>,
    auth: BearerAuth,
) -> impl Responder {
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) => {
            let user_id = claims.sub;
            let result = sqlx::query_as!(
                User,
                "SELECT * FROM users WHERE id = $1",
                user_id
            )
                .fetch_optional(pool.get_ref())
                .await;

            match result {
                Ok(Some(user)) => {
                    let user_response: UserResponse = user.into();
                    HttpResponse::Ok().json(user_response)
                },
                Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Not Found",
                    "message": "User not found"
                })),
                Err(e) => {
                    error!("Failed to get user: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal Server Error",
                        "message": "Failed to get user"
                    }))
                }
            }
        },
        Err(_) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid token"
        })),
    }
}

async fn fetch_user_by_id(pool: web::Data<PgPool>, user_id: Uuid) -> HttpResponse {
    let result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE id = $1",
        user_id
    )
        .fetch_optional(pool.get_ref())
        .await;

    match result {
        Ok(Some(user)) => {
            info!("User found: ID = {}", user_id);
            let user_response: UserResponse = user.into();
            HttpResponse::Ok().json(user_response)
        },
        Ok(None) => {
            warn!("User not found: ID = {}", user_id);
            HttpResponse::NotFound().json(json!({
                "error": "Not Found",
                "message": "User not found"
            }))
        },
        Err(e) => {
            error!("Database error while fetching user {}: {:?}", user_id, e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Internal Server Error",
                "message": "Failed to retrieve user information"
            }))
        }
    }
}

#[put("/users/{id}")]
pub async fn update_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    user_input: web::Json<UserInput>,
    auth: BearerAuth,
) -> impl Responder {
    let user_id = id.into_inner();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) if claims.sub == user_id => {
            let validated_user = match validate_and_sanitize_user_input(user_input.into_inner()) {
                Ok(user) => user,
                Err(errors) => return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Bad Request",
                    "messages": errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>()
                })),
            };

            let current_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
                .fetch_optional(pool.get_ref())
                .await;

            match current_user {
                Ok(Some(current_user)) => {
                    let new_username = validated_user.username;
                    let new_password_hash = match validated_user.password {
                        Some(password) => hash(&password, DEFAULT_COST).unwrap(),
                        None => current_user.password_hash,
                    };
                    let result = sqlx::query_as!(
                        User,
                        r#"
                        UPDATE users
                        SET username = $1, password_hash = $2, email = $3
                        WHERE id = $4
                        RETURNING *
                        "#,
                        new_username,
                        new_password_hash,
                        validated_user.email,
                        current_user.id
                    )
                        .fetch_one(pool.get_ref())
                        .await;

                    match result {
                        Ok(updated_user) => {
                            let user_response: UserResponse = updated_user.into();
                            HttpResponse::Ok().json(user_response)
                        },
                        Err(e) => {
                            error!("Failed to update user: {:?}", e);
                            HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Internal Server Error",
                                "message": "Failed to update user"
                            }))
                        }
                    }
                },
                Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Not Found",
                    "message": "User not found"
                })),
                Err(e) => {
                    error!("Failed to get user for update: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal Server Error",
                        "message": "Failed to update user"
                    }))
                }
            }
        },
        Ok(_) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Forbidden",
            "message": "Access denied: You can only update your own information"
        })),
        Err(_) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized",
            "message": "Invalid token"
        })),
    }
}

/// Handler for deleting a user
#[delete("/users/{id}")]
pub async fn delete_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    let user_id = id.into_inner();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // Validate JWT and check user authorization
    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) if claims.sub == user_id => {
            // Proceed with deleting user
            let result = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
                .execute(pool.get_ref())
                .await;

            match result {
                Ok(ref deleted) if deleted.rows_affected() > 0 => HttpResponse::NoContent().finish(),
                Ok(_) => HttpResponse::NotFound().json("User not found"),
                Err(e) => {
                    error!("Failed to delete user: {:?}", e);
                    HttpResponse::InternalServerError().json("Failed to delete user")
                }
            }
        },
        Ok(_) => HttpResponse::Forbidden().json("Access denied: You can only delete your own account"),
        Err(_) => HttpResponse::Unauthorized().json("Invalid token"),
    }
}

/// Generate a random verification token
fn generate_verification_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}



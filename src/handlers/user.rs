use actix_web::{web, HttpResponse, Responder, get, put, delete};
use sqlx::PgPool;
use crate::models::user::{User, UserResponse};
use crate::email::EmailService;
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use log::{debug, error, info, warn};
use chrono::{Utc, Duration};
use crate::auth;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::Deserialize;
use std::convert::TryFrom;
use crate::validation::{UserInput, LoginInput, validate_and_sanitize_user_input, validate_and_sanitize_login_input, sanitize_input};

/// Struct to represent the token query parameter
#[derive(Deserialize)]
pub struct TokenQuery {
    token: String,
}

impl TokenQuery {
    /// Getter method for token
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Implementation of TryFrom for TokenQuery to validate the token format
impl TryFrom<web::Query<TokenQuery>> for TokenQuery {
    type Error = actix_web::Error;

    fn try_from(query: web::Query<TokenQuery>) -> Result<Self, Self::Error> {
        // Validate token: ensure it's exactly 32 alphanumeric characters
        if !query.token.chars().all(|c| c.is_ascii_alphanumeric()) || query.token.len() != 32 {
            return Err(actix_web::error::ErrorBadRequest("Invalid token format"));
        }
        Ok(query.0)
    }
}

/// Handler for user registration
///
/// # API Example
/// POST /users/register
/// Content-Type: application/json
///
/// {
///     "username": "newuser",
///     "email": "newuser@example.com",
///     "password": "securepassword123"
/// }
///
/// # Response
/// 201 Created
/// {
///     "id": "123e4567-e89b-12d3-a456-426614174000",
///     "username": "newuser",
///     "email": "newuser@example.com",
///     "is_email_verified": false,
///     "created_at": "2023-04-20T12:00:00Z"
/// }
pub async fn create_user(pool: web::Data<PgPool>, user: web::Json<UserInput>) -> impl Responder {
    match validate_and_sanitize_user_input(user.into_inner()) {
        Ok(validated_user) => {
            debug!("Received create_user request at /users/register");
            info!("Attempting to create user: {:?}", validated_user);

            // Hash the password
            let password_hash = match validated_user.password {
                Some(password) => match hash(&password, DEFAULT_COST) {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!("Failed to hash password: {:?}", e);
                        return HttpResponse::InternalServerError().json("Failed to create user");
                    }
                },
                None => return HttpResponse::BadRequest().json("Password is required for user creation"),
            };

            // Generate verification token and expiration
            let verification_token = generate_verification_token();
            let verification_token_expires_at = Utc::now() + Duration::hours(24);

            // Get current timestamp for created_at and updated_at
            let now = Utc::now();

            // Insert new user into the database
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
                "user" // Set default role to "user"
            )
            .fetch_one(pool.get_ref())
            .await;

            match result {
                Ok(user) => {
                    // Send verification email
                    let email_service = EmailService::new();
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
                            HttpResponse::InternalServerError().json("User created but failed to send verification email")
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to create user: {:?}", e);
                    HttpResponse::InternalServerError().json(format!("Failed to create user: {:?}", e))
                }
            }
        },
        Err(errors) => {
            HttpResponse::BadRequest().json(errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>())
        }
    }
}

/// Handler for user login
///
/// # API Example
/// POST /users/login
/// Content-Type: application/json
///
/// {
///     "username": "existinguser",
///     "password": "correctpassword123"
/// }
///
/// # Response
/// 200 OK
/// {
///     "message": "Login successful",
///     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///     "user": {
///         "id": "123e4567-e89b-12d3-a456-426614174000",
///         "username": "existinguser",
///         "email": "existinguser@example.com",
///         "is_email_verified": true,
///         "created_at": "2023-04-19T10:30:00Z"
///     }
/// }
pub async fn login_user(pool: web::Data<PgPool>, user: web::Json<LoginInput>) -> impl Responder {
    let validated_user = match validate_and_sanitize_login_input(user.into_inner()) {
        Ok(user) => user,
        Err(errors) => return HttpResponse::BadRequest().json(errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>()),
    };

    // Fetch user from database
    let user_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        validated_user.username
    )
        .fetch_optional(pool.get_ref())
        .await;

    match user_result {
        Ok(Some(db_user)) => {
            // Check if email is verified
            if !db_user.is_email_verified {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "message": "Email has not been verified yet. Please check your email for the verification link.",
                    "error_type": "email_not_verified"
                }));
            }

            // Verify password
            match verify(&validated_user.password, &db_user.password_hash) {
                Ok(true) => {
                    // Generate JWT token
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
                            HttpResponse::InternalServerError().json("Error during login")
                        }
                    }
                },
                Ok(false) => HttpResponse::Unauthorized().json("Invalid username or password"),
                Err(e) => {
                    error!("Error verifying password: {:?}", e);
                    HttpResponse::InternalServerError().json("Error verifying password")
                },
            }
        },
        Ok(None) => HttpResponse::Unauthorized().json("Invalid username or password"),
        Err(e) => {
            error!("Database error during login: {:?}", e);
            HttpResponse::InternalServerError().json("Error logging in")
        }
    }
}

/// Handler for email verification
///
/// # API Example
/// GET /users/verify?token=abcdef1234567890abcdef1234567890
///
/// # Response
/// 302 Found
/// Location: /email_verified.html
pub async fn verify_email(
    pool: web::Data<PgPool>,
    token_query: web::Query<TokenQuery>,
) -> Result<impl Responder, actix_web::Error> {
    let token = TokenQuery::try_from(token_query)?;
    let sanitized_token = sanitize_input(token.token());

    debug!("Received email verification request with token: {}", sanitized_token);

    // Update user's email verification status
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
                .append_header((actix_web::http::header::LOCATION, "/email_verified.html"))
                .finish())
        },
        Ok(None) => {
            warn!("Invalid or expired verification token");
            Ok(HttpResponse::BadRequest().content_type("text/html").body(
                "<html><body><h1>Invalid or Expired Verification Token</h1><p>Please request a new verification email.</p></body></html>"
            ))
        },
        Err(e) => {
            error!("Failed to verify email: {:?}", e);
            Ok(HttpResponse::InternalServerError().content_type("text/html").body(
                "<html><body><h1>Error</h1><p>An error occurred while verifying your email. Please try again later.</p></body></html>"
            ))
        }
    }
}

/// Handler for getting user information
///
/// # API Example
/// GET /api/users/123e4567-e89b-12d3-a456-426614174000
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
///
/// # Response
/// 200 OK
/// {
///     "id": "123e4567-e89b-12d3-a456-426614174000",
///     "username": "existinguser",
///     "email": "existinguser@example.com",
///     "is_email_verified": true,
///     "created_at": "2023-04-19T10:30:00Z"
/// }
#[get("/users/{id}")]
pub async fn get_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    let user_id = id.into_inner();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Validate JWT and check user authorization
    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) if claims.sub == user_id => {
            // Proceed with fetching user info
            let result = sqlx::query_as!(
                User,
                "SELECT * FROM users WHERE id = $1",
                user_id
            )
            .fetch_optional(pool.get_ref())
            .await;

            match result {
                Ok(Some(user)) => {
                    info!("User found: {:?}", user);
                    let user_response: UserResponse = user.into();
                    HttpResponse::Ok().json(user_response)
                },
                Ok(None) => {
                    warn!("User not found for ID: {}", user_id);
                    HttpResponse::NotFound().json(serde_json::json!({
                        "error": "Not Found",
                        "message": "User not found"
                    }))
                },
                Err(e) => {
                    error!("Failed to get user: {:?}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Internal Server Error",
                        "message": "Failed to get user"
                    }))
                }
            }
        },
        Ok(_) => HttpResponse::Forbidden().json("Access denied: You can only view your own information"),
        Err(_) => HttpResponse::Unauthorized().json("Invalid token"),
    }
}

/// Handler for updating user information
///
/// # API Example
/// PUT /api/users/123e4567-e89b-12d3-a456-426614174000
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
/// Content-Type: application/json
///
/// {
///     "username": "updatedusername",
///     "password": "newpassword123"
/// }
///
/// # Response
/// 200 OK
/// {
///     "id": "123e4567-e89b-12d3-a456-426614174000",
///     "username": "updatedusername",
///     "email": "existinguser@example.com",
///     "is_email_verified": true,
///     "created_at": "2023-04-19T10:30:00Z"
/// }
#[put("/users/{id}")]
pub async fn update_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    user_input: web::Json<UserInput>,
    auth: BearerAuth,
) -> impl Responder {
    let user_id = id.into_inner();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Validate JWT and check user authorization
    match auth::validate_jwt(auth.token(), &jwt_secret) {
        Ok(claims) if claims.sub == user_id => {
            let validated_user = match validate_and_sanitize_user_input(user_input.into_inner()) {
                Ok(user) => user,
                Err(errors) => return HttpResponse::BadRequest().json(errors.into_iter().map(|e| e.to_string()).collect::<Vec<String>>()),
            };

            let current_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
                .fetch_optional(pool.get_ref())
                .await;

            match current_user {
                Ok(Some(current_user)) => {
                    let new_username = validated_user.username;
                    let new_password_hash = match validated_user.password {
                        Some(password) => hash(&password, DEFAULT_COST).unwrap(),
                        None => current_user.password_hash,  // Keep the existing password if not provided
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
                            HttpResponse::InternalServerError().json("Failed to update user")
                        }
                    }
                },
                Ok(None) => HttpResponse::NotFound().json("User not found"),
                Err(e) => {
                    error!("Failed to get user for update: {:?}", e);
                    HttpResponse::InternalServerError().json("Failed to update user")
                }
            }
        },
        Ok(_) => HttpResponse::Forbidden().json("Access denied: You can only update your own information"),
        Err(_) => HttpResponse::Unauthorized().json("Invalid token"),
    }
}

/// Handler for deleting a user
///
/// # API Example
/// DELETE /api/users/123e4567-e89b-12d3-a456-426614174000
/// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
///
/// # Response
/// 204 No Content
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
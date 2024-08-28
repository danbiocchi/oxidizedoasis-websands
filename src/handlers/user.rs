use actix_web::{web, HttpResponse, Responder, get, put, delete};
use sqlx::PgPool;
use crate::models::user::{User, UserResponse, CreateUser, LoginUser, UpdateUser};
use crate::email::EmailService;
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use log::{debug, error, info, warn};
use chrono::{Utc, Duration};
use crate::auth;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::Deserialize;
use std::convert::TryFrom;

#[derive(Deserialize)]
pub struct TokenQuery {
    token: String,
}

impl TokenQuery {
    // Getter method for token
    pub fn token(&self) -> &str {
        &self.token
    }
}

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

pub async fn create_user(pool: web::Data<PgPool>, user: web::Json<CreateUser>) -> impl Responder {
    debug!("Received create_user request at /users/register");
    info!("Attempting to create user: {:?}", user);

    // Log the raw request
    debug!("Raw request: {:?}", &user);

    let password_hash = match hash(user.password.as_bytes(), DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to create user");
        }
    };

    let verification_token = generate_verification_token();
    let verification_token_expires_at = Utc::now() + Duration::hours(24);

    let result = sqlx::query_as!(
        User,
        r#"INSERT INTO users (id, username, email, password_hash, is_email_verified, verification_token, verification_token_expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *"#,
        Uuid::new_v4(),
        user.username,
        user.email,
        password_hash,
        false,
        verification_token,
        verification_token_expires_at
    )
        .fetch_one(pool.get_ref())
        .await;

    match result {
        Ok(user) => {
            let email_service = EmailService::new();
            match email_service.send_verification_email(user.email.as_deref().unwrap_or_default(), &verification_token) {
                Ok(_) => {
                    info!("Verification email sent to: {}", user.email.as_deref().unwrap_or_default());
                    let user_response: UserResponse = user.into();
                    HttpResponse::Created().json(user_response)
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
}

pub async fn login_user(pool: web::Data<PgPool>, user: web::Json<LoginUser>) -> impl Responder {
    let user_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        user.username
    )
        .fetch_optional(pool.get_ref())
        .await;

    match user_result {
        Ok(Some(db_user)) => {
            if !db_user.is_email_verified {
                return HttpResponse::Unauthorized().json("Email not verified");
            }

            match verify(&user.password, &db_user.password_hash) {
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

pub async fn verify_email(
    pool: web::Data<PgPool>,
    token_query: web::Query<TokenQuery>,
) -> Result<impl Responder, actix_web::Error> {
    let token = TokenQuery::try_from(token_query)?;

    debug!("Received email verification request with token: {}", token.token());

    let result = sqlx::query!(
        r#"
        UPDATE users
        SET is_email_verified = TRUE, verification_token = NULL, verification_token_expires_at = NULL
        WHERE verification_token = $1 AND verification_token_expires_at > CURRENT_TIMESTAMP
        RETURNING id
        "#,
        token.token()
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

#[get("/{id}")]
pub async fn get_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, _: BearerAuth) -> impl Responder {
    let result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE id = $1",
        id.into_inner()
    )
        .fetch_optional(pool.get_ref())
        .await;

    match result {
        Ok(Some(user)) => {
            let user_response: UserResponse = user.into();
            HttpResponse::Ok().json(user_response)
        },
        Ok(None) => HttpResponse::NotFound().json("User not found"),
        Err(e) => {
            error!("Failed to get user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get user")
        }
    }
}

#[put("/{id}")]
pub async fn update_user(
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    user: web::Json<UpdateUser>,
    _: BearerAuth
) -> impl Responder {
    let current_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id.into_inner())
        .fetch_optional(pool.get_ref())
        .await;

    match current_user {
        Ok(Some(current_user)) => {
            let new_username = user.username.as_ref().unwrap_or(&current_user.username);
            let new_password_hash = match &user.password {
                Some(new_password) => hash(new_password.as_bytes(), DEFAULT_COST).unwrap(),
                None => current_user.password_hash,
            };

            let result = sqlx::query_as!(
                User,
                r#"
                UPDATE users
                SET username = $1, password_hash = $2
                WHERE id = $3
                RETURNING *
                "#,
                new_username,
                new_password_hash,
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
}

#[delete("/{id}")]
pub async fn delete_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, _: BearerAuth) -> impl Responder {
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id.into_inner())
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
}

fn generate_verification_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect()
}
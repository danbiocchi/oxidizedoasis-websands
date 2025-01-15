use actix_web::{web, HttpResponse, Responder, http::header};
use sqlx::PgPool;
use uuid::Uuid;
use std::sync::Arc;
use log::{debug, error, info, warn};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde_json::json;
use crate::core::user::{UserRepository, UserService};
use crate::core::auth::AuthService;
use crate::core::email::EmailServiceTrait;
use crate::common::validation::{UserInput, LoginInput, TokenQuery};
use crate::core::user::model::{PasswordResetRequest, PasswordResetSubmit};

pub struct UserHandler {
    user_service: Arc<UserService>,
    auth_service: Arc<AuthService>,
}

impl UserHandler {
    pub fn new(pool: PgPool, email_service: Arc<dyn EmailServiceTrait>) -> Self {
        let user_repo = UserRepository::new(pool.clone());
        let user_service = Arc::new(UserService::new(user_repo, email_service));
        let auth_service = Arc::new(AuthService::new(pool, std::env::var("JWT_SECRET").expect("JWT_SECRET must be set")));

        Self {
            user_service,
            auth_service,
        }
    }

    pub async fn create_user(
        &self,
        user_input: web::Json<UserInput>,
    ) -> impl Responder {
        debug!("Received create_user request");

        match self.user_service.create_user(user_input.into_inner()).await {
            Ok((user, _)) => {
                info!("User created successfully: {}", user.id);
                HttpResponse::Created().json(json!({
                    "success": true,
                    "message": "User created successfully. Please check your email for verification.",
                    "data": {
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_email_verified": user.is_email_verified,
                            "created_at": user.created_at
                        }
                    }
                }))
            },
            Err(e) => {
                error!("Failed to create user: {:?}", e);
                HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": e.to_string(),
                    "error": e.to_string()
                }))
            }
        }
    }

    pub async fn login_user(
        &self,
        login_input: web::Json<LoginInput>,
    ) -> impl Responder {
        match self.auth_service.login(login_input.into_inner()).await {
            Ok((token, user)) => {
                info!("User logged in successfully: {}", user.id);
                HttpResponse::Ok().json(json!({
                    "success": true,
                    "message": "Login successful",
                    "data": {
                        "token": token,
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "is_email_verified": user.is_email_verified,
                            "created_at": user.created_at
                        }
                    }
                }))
            },
            Err(e) => {
                match e.to_string().as_str() {
                    "Email not verified" => {
                        HttpResponse::Unauthorized().json(json!({
                            "success": false,
                            "message": "Email has not been verified yet. Please check your email for the verification link.",
                            "error_type": "email_not_verified"
                        }))
                    },
                    _ => {
                        error!("Login error: {:?}", e);
                        HttpResponse::Unauthorized().json(json!({
                            "success": false,
                            "message": "Invalid username or password",
                            "error": "Invalid credentials"
                        }))
                    }
                }
            }
        }
    }

    pub async fn verify_email(
        &self,
        token_query: web::Query<TokenQuery>,
    ) -> Result<impl Responder, actix_web::Error> {
        let token = TokenQuery::try_from(token_query)?;
        debug!("Processing email verification token");

        match self.user_service.verify_email(token.token()).await {
            Ok(()) => {
                info!("Email verified successfully");
                Ok(HttpResponse::Found()
                    .append_header((header::LOCATION, "/email_verified"))
                    .finish())
            },
            Err(e) => {
                error!("Email verification failed: {:?}", e);
                Ok(HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "The verification link is invalid or has expired",
                    "error": "Invalid verification token"
                })))
            }
        }
    }

    pub async fn get_user(
        &self,
        user_id: web::Path<Uuid>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_auth(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    warn!("Unauthorized access attempt: User {} tried to access data for user {}", claims.sub, user_id);
                    return HttpResponse::Forbidden().json(json!({
                        "success": false,
                        "message": "Access denied: You can only view your own information",
                        "error": "Unauthorized access"
                    }));
                }

                match self.user_service.get_user_by_id(*user_id).await {
                    Ok(user) => HttpResponse::Ok().json(json!({
                        "success": true,
                        "data": {
                            "user": {
                                "id": user.id,
                                "username": user.username,
                                "email": user.email,
                                "is_email_verified": user.is_email_verified,
                                "created_at": user.created_at
                            }
                        }
                    })),
                    Err(e) => {
                        error!("Failed to fetch user: {:?}", e);
                        HttpResponse::NotFound().json(json!({
                            "success": false,
                            "message": "User not found",
                            "error": "Not found"
                        }))
                    }
                }
            },
            Err(e) => {
                warn!("Invalid token: {:?}", e);
                HttpResponse::Unauthorized().json(json!({
                    "success": false,
                    "message": "Invalid token",
                    "error": "Authentication failed"
                }))
            }
        }
    }

    pub async fn get_current_user(
        &self,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_auth(auth.token()).await {
            Ok(claims) => {
                match self.user_service.get_user_by_id(claims.sub).await {
                    Ok(user) => HttpResponse::Ok().json(json!({
                        "success": true,
                        "data": {
                            "user": {
                                "id": user.id,
                                "username": user.username,
                                "email": user.email,
                                "is_email_verified": user.is_email_verified,
                                "created_at": user.created_at
                            }
                        }
                    })),
                    Err(e) => {
                        error!("Failed to fetch current user: {:?}", e);
                        HttpResponse::NotFound().json(json!({
                            "success": false,
                            "message": "User not found",
                            "error": "Not found"
                        }))
                    }
                }
            },
            Err(e) => {
                warn!("Invalid token: {:?}", e);
                HttpResponse::Unauthorized().json(json!({
                    "success": false,
                    "message": "Invalid token",
                    "error": "Authentication failed"
                }))
            }
        }
    }

    pub async fn update_user(
        &self,
        user_id: web::Path<Uuid>,
        user_input: web::Json<UserInput>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_auth(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    return HttpResponse::Forbidden().json(json!({
                        "success": false,
                        "message": "Access denied: You can only update your own information",
                        "error": "Unauthorized access"
                    }));
                }

                match self.user_service.update_user(*user_id, user_input.into_inner()).await {
                    Ok(updated_user) => HttpResponse::Ok().json(json!({
                        "success": true,
                        "message": "User updated successfully",
                        "data": {
                            "user": {
                                "id": updated_user.id,
                                "username": updated_user.username,
                                "email": updated_user.email,
                                "is_email_verified": updated_user.is_email_verified,
                                "created_at": updated_user.created_at
                            }
                        }
                    })),
                    Err(e) => {
                        error!("Failed to update user: {:?}", e);
                        HttpResponse::InternalServerError().json(json!({
                            "success": false,
                            "message": "Failed to update user",
                            "error": "Internal server error"
                        }))
                    }
                }
            },
            Err(_) => HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Invalid token",
                "error": "Authentication failed"
            }))
        }
    }

    pub async fn request_password_reset(
        &self,
        request: web::Json<PasswordResetRequest>,
    ) -> impl Responder {
        debug!("Received password reset request");

        match self.user_service.request_password_reset(&request.email).await {
            Ok(()) => {
                info!("Password reset email sent successfully");
                HttpResponse::Ok().json(json!({
                    "success": true,
                    "message": "If an account exists with that email, you will receive password reset instructions."
                }))
            },
            Err(e) => {
                error!("Password reset request failed: {:?}", e);
                // Return success even on error to prevent email enumeration
                HttpResponse::Ok().json(json!({
                    "success": true,
                    "message": "If an account exists with that email, you will receive password reset instructions."
                }))
            }
        }
    }

    pub async fn verify_reset_token(
        &self,
        token_query: web::Query<TokenQuery>,
    ) -> Result<impl Responder, actix_web::Error> {
        let token = TokenQuery::try_from(token_query)?;
        debug!("Verifying password reset token");

        match self.user_service.verify_reset_token(token.token()).await {
            Ok(()) => {
                info!("Password reset token verified successfully");
                Ok(HttpResponse::Found()
                    .append_header((header::LOCATION, format!("/password-reset/new?token={}", token.token())))
                    .finish())
            },
            Err(e) => {
                error!("Password reset token verification failed: {:?}", e);
                Ok(HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "The password reset link is invalid or has expired",
                    "error": "Invalid reset token"
                })))
            }
        }
    }

    pub async fn reset_password(
        &self,
        reset_data: web::Json<PasswordResetSubmit>,
    ) -> impl Responder {
        debug!("Processing password reset");

        if reset_data.new_password != reset_data.confirm_password {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Passwords do not match",
                "error": "Password mismatch"
            }));
        }

        match self.user_service.reset_password(&reset_data.token, &reset_data.new_password).await {
            Ok(()) => {
                info!("Password reset successful");
                HttpResponse::Ok().json(json!({
                    "success": true,
                    "message": "Password has been reset successfully. You can now log in with your new password."
                }))
            },
            Err(e) => {
                error!("Password reset failed: {:?}", e);
                HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": e.to_string(),
                    "error": "Password reset failed"
                }))
            }
        }
    }

    pub async fn delete_user(
        &self,
        user_id: web::Path<Uuid>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_auth(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    return HttpResponse::Forbidden().json(json!({
                        "success": false,
                        "message": "Access denied: You can only delete your own account",
                        "error": "Unauthorized access"
                    }));
                }

                match self.user_service.delete_user(*user_id).await {
                    Ok(()) => HttpResponse::Ok().json(json!({
                        "success": true,
                        "message": "User deleted successfully"
                    })),
                    Err(e) => {
                        error!("Failed to delete user: {:?}", e);
                        HttpResponse::InternalServerError().json(json!({
                            "success": false,
                            "message": "Failed to delete user",
                            "error": "Internal server error"
                        }))
                    }
                }
            },
            Err(_) => HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Invalid token",
                "error": "Authentication failed"
            }))
        }
    }
}

// Factory function to create handler instance
pub fn create_handler(pool: PgPool, email_service: Arc<dyn EmailServiceTrait>) -> UserHandler {
    UserHandler::new(pool, email_service)
}

// Route handler functions
pub async fn create_user_handler(
    handler: web::Data<UserHandler>,
    user_input: web::Json<UserInput>,
) -> impl Responder {
    handler.create_user(user_input).await
}

pub async fn login_user_handler(
    handler: web::Data<UserHandler>,
    login_input: web::Json<LoginInput>,
) -> impl Responder {
    handler.login_user(login_input).await
}

pub async fn verify_email_handler(
    handler: web::Data<UserHandler>,
    token_query: web::Query<TokenQuery>,
) -> Result<impl Responder, actix_web::Error> {
    handler.verify_email(token_query).await
}

pub async fn get_user_handler(
    handler: web::Data<UserHandler>,
    user_id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    handler.get_user(user_id, auth).await
}

pub async fn get_current_user_handler(
    handler: web::Data<UserHandler>,
    auth: BearerAuth,
) -> impl Responder {
    handler.get_current_user(auth).await
}

pub async fn update_user_handler(
    handler: web::Data<UserHandler>,
    user_id: web::Path<Uuid>,
    user_input: web::Json<UserInput>,
    auth: BearerAuth,
) -> impl Responder {
    handler.update_user(user_id, user_input, auth).await
}

pub async fn request_password_reset_handler(
    handler: web::Data<UserHandler>,
    request: web::Json<PasswordResetRequest>,
) -> impl Responder {
    handler.request_password_reset(request).await
}

pub async fn verify_reset_token_handler(
    handler: web::Data<UserHandler>,
    token_query: web::Query<TokenQuery>,
) -> Result<impl Responder, actix_web::Error> {
    handler.verify_reset_token(token_query).await
}

pub async fn reset_password_handler(
    handler: web::Data<UserHandler>,
    reset_data: web::Json<PasswordResetSubmit>,
) -> impl Responder {
    handler.reset_password(reset_data).await
}

pub async fn delete_user_handler(
    handler: web::Data<UserHandler>,
    user_id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    handler.delete_user(user_id, auth).await
}

// src/api/handlers/user_handler.rs
use actix_web::{web, HttpResponse, Responder, http::header};
use sqlx::PgPool;
use uuid::Uuid;
use std::sync::Arc;
use log::{debug, error, info, warn};
use actix_web_httpauth::extractors::bearer::BearerAuth;

use crate::core::user::{UserRepository, UserService};
use crate::core::auth::AuthService;
use crate::core::email::EmailServiceTrait;
use crate::common::validation::{UserInput, LoginInput, TokenQuery};
use crate::api::responses::user_response::ApiResponse;

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
            Ok((user, email)) => {
                info!("User created successfully: {}", user.id);
                HttpResponse::Created().json(ApiResponse::success_with_message(
                    "User created successfully",
                    json!({
                        "user": user,
                        "email": email
                    })
                ))
            },
            Err(e) => {
                error!("Failed to create user: {:?}", e);
                HttpResponse::BadRequest().json(ApiResponse::<()>::error(e))
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
                HttpResponse::Ok().json(ApiResponse::success_with_message(
                    "Login successful",
                    json!({
                        "token": token,
                        "user": user
                    })
                ))
            },
            Err(e) => {
                match e.to_string().as_str() {
                    "Email not verified" => {
                        HttpResponse::Unauthorized().json(ApiResponse::<()>::error_with_type(
                            "Email has not been verified yet. Please check your email for the verification link.",
                            "email_not_verified"
                        ))
                    },
                    _ => {
                        error!("Login error: {:?}", e);
                        HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
                            "Invalid username or password"
                        ))
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
                Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                    "The verification link is invalid or has expired"
                )))
            }
        }
    }

    pub async fn get_user(
        &self,
        user_id: web::Path<Uuid>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_token(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    warn!("Unauthorized access attempt: User {} tried to access data for user {}", claims.sub, user_id);
                    return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                        "Access denied: You can only view your own information"
                    ));
                }

                match self.user_service.get_user_by_id(*user_id).await {
                    Ok(user) => HttpResponse::Ok().json(ApiResponse::success(user)),
                    Err(e) => {
                        error!("Failed to fetch user: {:?}", e);
                        HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found"))
                    }
                }
            },
            Err(e) => {
                warn!("Invalid token: {:?}", e);
                HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid token"))
            }
        }
    }

    pub async fn get_current_user(
        &self,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_token(auth.token()).await {
            Ok(claims) => {
                match self.user_service.get_user_by_id(claims.sub).await {
                    Ok(user) => HttpResponse::Ok().json(ApiResponse::success(user)),
                    Err(e) => {
                        error!("Failed to fetch current user: {:?}", e);
                        HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found"))
                    }
                }
            },
            Err(e) => {
                warn!("Invalid token: {:?}", e);
                HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid token"))
            }
        }
    }

    pub async fn update_user(
        &self,
        user_id: web::Path<Uuid>,
        user_input: web::Json<UserInput>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_token(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                        "Access denied: You can only update your own information"
                    ));
                }

                match self.user_service.update_user(*user_id, user_input.into_inner()).await {
                    Ok(updated_user) => HttpResponse::Ok().json(ApiResponse::success(updated_user)),
                    Err(e) => {
                        error!("Failed to update user: {:?}", e);
                        HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                            "Failed to update user"
                        ))
                    }
                }
            },
            Err(_) => HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid token"))
        }
    }

    pub async fn delete_user(
        &self,
        user_id: web::Path<Uuid>,
        auth: BearerAuth,
    ) -> impl Responder {
        match self.auth_service.validate_token(auth.token()).await {
            Ok(claims) => {
                if claims.sub != *user_id {
                    return HttpResponse::Forbidden().json(ApiResponse::<()>::error(
                        "Access denied: You can only delete your own account"
                    ));
                }

                match self.user_service.delete_user(*user_id).await {
                    Ok(()) => HttpResponse::NoContent().finish(),
                    Err(e) => {
                        error!("Failed to delete user: {:?}", e);
                        HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                            "Failed to delete user"
                        ))
                    }
                }
            },
            Err(_) => HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid token"))
        }
    }
}

// Factory function to create handler instance
pub fn create_handler(pool: PgPool, email_service: Arc<dyn EmailServiceTrait>) -> UserHandler {
    UserHandler::new(pool, email_service)
}

// Route handler functions that use the UserHandler instance
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

pub async fn delete_user_handler(
    handler: web::Data<UserHandler>,
    user_id: web::Path<Uuid>,
    auth: BearerAuth,
) -> impl Responder {
    handler.delete_user(user_id, auth).await
}
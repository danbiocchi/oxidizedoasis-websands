use actix_web::{web, HttpResponse, Responder, get, post, put, delete};
use sqlx::PgPool;
use crate::models::user::{User, UserResponse, CreateUser, LoginUser, UpdateUser};
use bcrypt::{verify, hash, DEFAULT_COST};
use uuid::Uuid;
use log::{error, info};
use crate::auth;
use actix_web_httpauth::extractors::bearer::BearerAuth;

#[post("/users")]
pub async fn create_user(pool: web::Data<PgPool>, user: web::Json<CreateUser>) -> impl Responder {
    let password_hash = match hash(user.password.as_bytes(), DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to create user");
        }
    };

    let result = sqlx::query_as!(
        User,
        "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3) RETURNING id, username, password_hash",
        Uuid::new_v4(),
        user.username,
        password_hash
    )
        .fetch_one(pool.get_ref())
        .await;

    match result {
        Ok(user) => {
            let user_response: UserResponse = user.into();
            HttpResponse::Ok().json(user_response)
        },
        Err(e) => {
            error!("Failed to create user: {:?}", e);
            HttpResponse::InternalServerError().json(format!("Failed to create user: {:?}", e))
        }
    }
}

#[get("/users/{id}")]
pub async fn get_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, _: BearerAuth) -> impl Responder {
    let result = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash FROM users WHERE id = $1",
        id.into_inner()
    )
        .fetch_optional(pool.get_ref())
        .await;

    match result {
        Ok(Some(user)) => {
            let user_response: UserResponse = user.into();
            HttpResponse::Ok().json(user_response)
        },
        Ok(None) => {
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            error!("Failed to get user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get user")
        }
    }
}

#[put("/users/{id}")]
pub async fn update_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, user: web::Json<UpdateUser>, _: BearerAuth) -> impl Responder {
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
                "UPDATE users SET username = $1, password_hash = $2 WHERE id = $3 RETURNING id, username, password_hash",
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
        Ok(None) => {
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            error!("Failed to get user for update: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to update user")
        }
    }
}

/// Handler for deleting a user
///
/// This function handles DELETE requests to "/users/{id}" endpoint.
/// It deletes the user with the specified ID from the database.
#[delete("/users/{id}")]
pub async fn delete_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, _: BearerAuth) -> impl Responder {
    // Attempt to delete the user from the database
    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id.into_inner())
        .execute(pool.get_ref())
        .await;

    // Handle the result of the database operation
    match result {
        Ok(ref deleted) if deleted.rows_affected() > 0 => {
            // If a user was deleted, return a 204 No Content response
            HttpResponse::NoContent().finish()
        },
        Ok(_) => {
            // If no user was found to delete, return a 404 Not Found response
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            // If there's a database error, log it and return a 500 Internal Server Error response
            error!("Failed to delete user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to delete user")
        }
    }
}

/// Handler for user login
///
/// This function handles POST requests to "/users/login" endpoint.
/// It verifies the provided username and password against the database.
#[post("/users/login")]
pub async fn login_user(pool: web::Data<PgPool>, user: web::Json<LoginUser>) -> impl Responder {
    let user_result = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash FROM users WHERE username = $1",
        user.username
    )
        .fetch_optional(pool.get_ref())
        .await;

    match user_result {
        Ok(Some(db_user)) => {
            match verify(&user.password, &db_user.password_hash) {
                Ok(true) => {
                    info!("User logged in successfully: {}", db_user.username);

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
                Ok(false) => {
                    HttpResponse::Unauthorized().json("Invalid username or password")
                },
                Err(e) => {
                    error!("Error verifying password: {:?}", e);
                    HttpResponse::InternalServerError().json("Error verifying password")
                },
            }
        },
        Ok(None) => {
            HttpResponse::Unauthorized().json("Invalid username or password")
        },
        Err(e) => {
            error!("Database error during login: {:?}", e);
            HttpResponse::InternalServerError().json("Error logging in")
        }
    }
}
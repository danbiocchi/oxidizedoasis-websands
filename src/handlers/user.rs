use actix_web::{web, HttpResponse, Responder, get, post, put, delete};
use sqlx::PgPool;
use crate::models::user::{User, CreateUser, LoginUser, UpdateUser};
use bcrypt::{verify, hash, DEFAULT_COST};
use uuid::Uuid;
use log::{error, info};

/// Handler for creating a new user
///
/// This function handles POST requests to "/users" endpoint.
/// It creates a new user with the provided username and password.
#[post("/users")]
pub async fn create_user(pool: web::Data<PgPool>, user: web::Json<CreateUser>) -> impl Responder {
    // Hash the provided password
    // We use bcrypt for secure password hashing
    let password_hash = match hash(user.password.as_bytes(), DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            // If hashing fails, log the error and return a 500 Internal Server Error response
            error!("Failed to hash password: {:?}", e);
            return HttpResponse::InternalServerError().json("Failed to create user");
        }
    };

    // Attempt to insert the new user into the database
    // We use SQLx to execute a SQL query with parameters
    let result = sqlx::query_as!(
        User,
        "INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3) RETURNING id, username, password_hash",
        Uuid::new_v4(),  // Generate a new UUID for the user
        user.username,
        password_hash
    )
        .fetch_one(pool.get_ref())
        .await;

    // Handle the result of the database operation
    match result {
        Ok(user) => {
            // If successful, return the created user as JSON with a 200 OK status
            HttpResponse::Ok().json(user)
        },
        Err(e) => {
            // If there's an error, log it and return a 500 Internal Server Error response
            error!("Failed to create user: {:?}", e);
            HttpResponse::InternalServerError().json(format!("Failed to create user: {:?}", e))
        }
    }
}

/// Handler for retrieving a user by ID
///
/// This function handles GET requests to "/users/{id}" endpoint.
/// It retrieves a user with the specified ID from the database.
#[get("/users/{id}")]
pub async fn get_user(pool: web::Data<PgPool>, id: web::Path<Uuid>) -> impl Responder {
    // Attempt to fetch the user from the database
    // We use SQLx to execute a SQL query with the provided user ID
    let result = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash FROM users WHERE id = $1",
        id.into_inner()
    )
        .fetch_optional(pool.get_ref())
        .await;

    // Handle the result of the database operation
    match result {
        Ok(Some(user)) => {
            // If a user is found, return it as JSON with a 200 OK status
            HttpResponse::Ok().json(user)
        },
        Ok(None) => {
            // If no user is found, return a 404 Not Found response
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            // If there's a database error, log it and return a 500 Internal Server Error response
            error!("Failed to get user: {:?}", e);
            HttpResponse::InternalServerError().json("Failed to get user")
        }
    }
}

/// Handler for updating a user
///
/// This function handles PUT requests to "/users/{id}" endpoint.
/// It updates the user with the specified ID with the provided information.
#[put("/users/{id}")]
pub async fn update_user(pool: web::Data<PgPool>, id: web::Path<Uuid>, user: web::Json<UpdateUser>) -> impl Responder {
    // First, fetch the current user data
    let current_user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id.into_inner())
        .fetch_optional(pool.get_ref())
        .await;

    match current_user {
        Ok(Some(current_user)) => {
            // Determine the new username (use the provided one or keep the current one)
            let new_username = user.username.as_ref().unwrap_or(&current_user.username);

            // Determine the new password hash (hash the new password if provided, or keep the current one)
            let new_password_hash = match &user.password {
                Some(new_password) => hash(new_password.as_bytes(), DEFAULT_COST).unwrap(),
                None => current_user.password_hash,
            };

            // Attempt to update the user in the database
            let result = sqlx::query_as!(
                User,
                "UPDATE users SET username = $1, password_hash = $2 WHERE id = $3 RETURNING id, username, password_hash",
                new_username,
                new_password_hash,
                current_user.id
            )
                .fetch_one(pool.get_ref())
                .await;

            // Handle the result of the database operation
            match result {
                Ok(updated_user) => {
                    // If successful, return the updated user as JSON with a 200 OK status
                    HttpResponse::Ok().json(updated_user)
                },
                Err(e) => {
                    // If there's an error, log it and return a 500 Internal Server Error response
                    error!("Failed to update user: {:?}", e);
                    HttpResponse::InternalServerError().json("Failed to update user")
                }
            }
        },
        Ok(None) => {
            // If no user is found, return a 404 Not Found response
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            // If there's a database error, log it and return a 500 Internal Server Error response
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
pub async fn delete_user(pool: web::Data<PgPool>, id: web::Path<Uuid>) -> impl Responder {
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
    // Attempt to fetch the user from the database by username
    let user_result = sqlx::query_as!(
        User,
        "SELECT id, username, password_hash FROM users WHERE username = $1",
        user.username
    )
        .fetch_optional(pool.get_ref())
        .await;

    // Handle the result of the database operation
    match user_result {
        Ok(Some(db_user)) => {
            // Verify the provided password against the stored hash
            match verify(&user.password, &db_user.password_hash) {
                Ok(true) => {
                    // Password is correct, log the successful login and return user data
                    info!("User logged in successfully: {}", db_user.username);
                    HttpResponse::Ok().json(db_user)
                },
                Ok(false) => {
                    // Password is incorrect, return a 401 Unauthorized response
                    HttpResponse::Unauthorized().json("Invalid username or password")
                },
                Err(e) => {
                    // If there's an error verifying the password, log it and return a 500 Internal Server Error
                    error!("Error verifying password: {:?}", e);
                    HttpResponse::InternalServerError().json("Error verifying password")
                },
            }
        },
        Ok(None) => {
            // If no user is found with the provided username, return a 401 Unauthorized response
            HttpResponse::Unauthorized().json("Invalid username or password")
        },
        Err(e) => {
            // If there's a database error, log it and return a 500 Internal Server Error response
            error!("Database error during login: {:?}", e);
            HttpResponse::InternalServerError().json("Error logging in")
        }
    }
}
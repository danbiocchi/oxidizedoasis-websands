use oxidizedoasis_websands::User;
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;
use chrono::Utc;
use std::env;
use log::{info, debug, warn};

async fn setup_test_db() -> PgPool {
    dotenv::from_filename(".env.test").ok();

    let su_database_url = env::var("TEST_SU_DATABASE_URL")
        .expect("TEST_SU_DATABASE_URL must be set in .env.test");
    let database_url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set in .env.test");
    let db_name = env::var("TEST_DB_NAME")
        .expect("TEST_DB_NAME must be set in .env.test");
    let db_user = env::var("TEST_DB_USER")
        .expect("TEST_DB_USER must be set in .env.test");

    debug!("Super user database URL: {}", su_database_url);
    debug!("Application database URL: {}", database_url);
    debug!("Database name: {}", db_name);
    debug!("Database user: {}", db_user);

    // Connect as superuser
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&su_database_url)
        .await
        .expect("Failed to connect to database as superuser");

    // Check if database exists, create if it doesn't
    let db_exists: bool = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(&db_name)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if database exists");

    if !db_exists {
        info!("Creating database '{}'", db_name);
        sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&pool)
            .await
            .expect("Failed to create database");
    }

    // Connect to the specific database
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to the specific database");

    // Ensure the application user exists
    let user_exists: bool = sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(&db_user)
        .fetch_one(&pool)
        .await
        .expect("Failed to check if user exists");

    if !user_exists {
        info!("Creating user '{}'", db_user);
        sqlx::query(&format!("CREATE USER \"{}\" WITH PASSWORD '{}'", db_user, env::var("TEST_DB_PASSWORD").unwrap()))
            .execute(&pool)
            .await
            .expect("Failed to create user");
    }

    // Grant privileges
    info!("Granting privileges to user '{}'", db_user);
    let grant_queries = vec![
        format!("GRANT ALL PRIVILEGES ON DATABASE \"{}\" TO \"{}\"", db_name, db_user),
        format!("GRANT ALL PRIVILEGES ON SCHEMA public TO \"{}\"", db_user),
        format!("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{}\"", db_user),
        format!("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{}\"", db_user),
        format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO \"{}\"", db_user),
        format!("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO \"{}\"", db_user),
    ];

    for query in grant_queries {
        match sqlx::query(&query).execute(&pool).await {
            Ok(_) => info!("Successfully executed: {}", query),
            Err(e) => warn!("Failed to execute: {}. Error: {:?}", query, e),
        }
    }

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}


async fn clean_test_db(pool: &PgPool) {
    sqlx::query!("DELETE FROM users")
        .execute(pool)
        .await
        .expect("Failed to clean test database");
}

#[actix_rt::test]
async fn test_create_user() {
    let pool = setup_test_db().await;
    clean_test_db(&pool).await;

    let new_user = User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        email: Some("testuser@example.com".to_string()),
        password_hash: "hashed_password".to_string(),
        is_email_verified: false,
        verification_token: Some("token".to_string()),
        verification_token_expires_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        role: "user".to_string(),
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, verification_token, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        new_user.id,
        new_user.username,
        new_user.email,
        new_user.password_hash,
        new_user.is_email_verified,
        new_user.verification_token,
        new_user.role,
        new_user.created_at,
        new_user.updated_at
    )
        .fetch_one(&pool)
        .await;

    assert!(result.is_ok(), "Failed to create user: {:?}", result.err());
}

#[actix_rt::test]
async fn test_read_user() {
    let pool = setup_test_db().await;
    clean_test_db(&pool).await;

    let user_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        user_id,
        "readuser",
        "readuser@example.com",
        "hashed_password",
        false,
        "user",
        Utc::now(),
        Utc::now()
    )
        .execute(&pool)
        .await
        .expect("Failed to create test user");

    let result = sqlx::query_as!(
        User,
        r#"SELECT * FROM users WHERE id = $1"#,
        user_id
    )
        .fetch_one(&pool)
        .await;

    assert!(result.is_ok(), "Failed to read user: {:?}", result.err());
    let user = result.unwrap();
    assert_eq!(user.username, "readuser");
    assert_eq!(user.email, Some("readuser@example.com".to_string()));
}
#[actix_rt::test]
async fn test_update_user() {
    let pool = setup_test_db().await;
    clean_test_db(&pool).await;

    let user_id = Uuid::new_v4();
    let insert_result = sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        user_id,
        "updateuser",
        "updateuser@example.com",
        "hashed_password",
        false,
        "user",
        Utc::now(),
        Utc::now()
    )
        .fetch_one(&pool)
        .await;

    assert!(insert_result.is_ok(), "Failed to insert user: {:?}", insert_result.err());

    // Verify the user was inserted
    let check_result = sqlx::query!(
        r#"SELECT * FROM users WHERE id = $1"#,
        user_id
    )
        .fetch_optional(&pool)
        .await;

    assert!(check_result.is_ok(), "Failed to check for inserted user: {:?}", check_result.err());
    let checked_user = check_result.unwrap();
    assert!(checked_user.is_some(), "User not found after insertion");

    let new_username = "updateduser";
    let result = sqlx::query!(
        r#"
        UPDATE users
        SET username = $1, updated_at = $2
        WHERE id = $3
        RETURNING *
        "#,
        new_username,
        Utc::now(),
        user_id
    )
        .fetch_one(&pool)
        .await;

    assert!(result.is_ok(), "Failed to update user: {:?}", result.err());
    let updated_user = result.unwrap();
    assert_eq!(updated_user.username, new_username);
}

#[actix_rt::test]
async fn test_delete_user() {
    let pool = setup_test_db().await;
    clean_test_db(&pool).await;

    let user_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        user_id,
        "deleteuser",
        "deleteuser@example.com",
        "hashed_password",
        false,
        "user",
        Utc::now(),
        Utc::now()
    )
        .execute(&pool)
        .await
        .expect("Failed to create test user");

    let result = sqlx::query!(
        r#"
        DELETE FROM users
        WHERE id = $1
        "#,
        user_id
    )
        .execute(&pool)
        .await;

    assert!(result.is_ok(), "Failed to delete user: {:?}", result.err());

    let user = sqlx::query!(
        r#"SELECT * FROM users WHERE id = $1"#,
        user_id
    )
        .fetch_optional(&pool)
        .await
        .expect("Failed to query for deleted user");

    assert!(user.is_none(), "User was not deleted");
}
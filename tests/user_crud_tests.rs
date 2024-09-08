use oxidizedoasis_websands::User;
use sqlx::{postgres::Postgres, Connection, PgConnection, PgPool, ConnectOptions};
use uuid::Uuid;
use chrono::Utc;
use std::env;
use std::str::FromStr;
use std::time::Duration;
use log::{info, error, debug};
use sqlx::migrate::MigrateDatabase;

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

    // Check if database exists, create if it doesn't
    if !Postgres::database_exists(&su_database_url).await.unwrap_or(false) {
        info!("Test database '{}' does not exist. Attempting to create...", db_name);
        match Postgres::create_database(&su_database_url).await {
            Ok(_) => info!("Test database '{}' created successfully", db_name),
            Err(e) => {
                error!("Failed to create test database '{}': {:?}", db_name, e);
                panic!("Failed to create test database");
            }
        }
    } else {
        info!("Test database '{}' already exists", db_name);
    }

    // Connect as super user to grant privileges
    info!("Connecting to database as super user");
    let mut su_conn = PgConnection::connect(&su_database_url).await
        .expect("Failed to connect as super user");

    info!("Granting privileges to application user '{}'", db_user);

    // Grant privileges to application user
    let grant_query = format!("GRANT ALL PRIVILEGES ON DATABASE \"{}\" TO \"{}\"", db_name, db_user);
    if let Err(e) = sqlx::query(&grant_query).execute(&mut su_conn).await {
        error!("Failed to grant privileges to '{}': {:?}", db_user, e);
        panic!("Failed to grant privileges");
    }

    // Close super user connection
    drop(su_conn);
    info!("Closed super user connection");

    // Set up connection pool with application user
    info!("Setting up connection pool for application user");
    let pool = PgPool::connect_with(
        sqlx::postgres::PgConnectOptions::from_str(&database_url)
            .expect("Failed to parse database URL")
            .application_name("oxidizedoasis_tests")
            .log_statements(log::LevelFilter::Debug)
            .log_slow_statements(log::LevelFilter::Warn, Duration::from_secs(1))
    )
        .await
        .expect("Failed to create connection pool");

    // Run migrations
    info!("Running database migrations");
    match sqlx::migrate!("./migrations").run(&pool).await {
        Ok(_) => info!("Migrations completed successfully"),
        Err(e) => {
            error!("Migration failed: {:?}", e);
            panic!("Failed to run migrations");
        }
    }

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
    sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
        .execute(&pool)
        .await
        .expect("Failed to create test user");

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
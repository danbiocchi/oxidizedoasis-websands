
/* 
use dotenv;
use oxidizedoasis_websands::{
    handlers::user::verify_email,
    models::user::User,
};
use actix_web::{test, web, App, dev::{Service, ServiceResponse}};
use actix_web::http::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{Utc, Duration};
use rand::Rng;

async fn get_test_db_pool() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set in .env.test");

    PgPool::connect(&database_url)
        .await
        .expect("Failed to create test database pool")
}

async fn clean_database(pool: &PgPool) {
    sqlx::query!("DELETE FROM users")
        .execute(pool)
        .await
        .expect("Failed to clean the database");
}

fn generate_token() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    const TOKEN_LEN: usize = 32;
    let mut rng = rand::thread_rng();

    (0..TOKEN_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

async fn setup_test_app(pool: web::Data<PgPool>) -> impl Service<actix_web::dev::ServiceRequest, Response = ServiceResponse, Error = actix_web::Error> {
    test::init_service(
        App::new()
            .app_data(pool.clone())
            .service(web::resource("/verify").to(verify_email))
    ).await
}

#[actix_rt::test]
async fn test_email_verification_with_valid_token() {
    dotenv::from_filename(".env.test").ok();

    let pool = web::Data::new(get_test_db_pool().await);
    clean_database(pool.get_ref()).await;

    let mut app = setup_test_app(pool.clone()).await;

    let user_id = Uuid::new_v4();
    let verification_token = generate_token();
    println!("Generated token: {}", verification_token);
    let expiration = Utc::now() + Duration::hours(24);
    let unique_username = format!("testuser_{}", Uuid::new_v4());

    sqlx::query!(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_email_verified, verification_token, verification_token_expires_at, created_at, updated_at, role)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        user_id,
        unique_username,
        "test@example.com",
        "hashed_password",
        false,
        &verification_token,
        expiration,
        Utc::now(),
        Utc::now(),
        "user"
    )
        .execute(pool.get_ref())
        .await
        .expect("Failed to insert test user");

    let req = test::TestRequest::get()
        .uri(&format!("/verify?token={}", verification_token))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    println!("Response status: {:?}", resp.status());
    println!("Response headers: {:?}", resp.headers());

    let status = resp.status();
    let body = test::read_body(resp).await;
    println!("Response body: {:?}", String::from_utf8_lossy(&body));

    let updated_user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE id = $1",
        user_id
    )
        .fetch_one(pool.get_ref())
        .await
        .expect("Failed to fetch updated user");

    println!("Updated user: {:?}", updated_user);

    assert_eq!(status, StatusCode::FOUND); // Expecting a redirect
    assert_eq!(resp.headers().get("location").unwrap(), "/email_verified.html");
    assert!(updated_user.is_email_verified, "User's email should be verified");
    assert!(updated_user.verification_token.is_none(), "Verification token should be removed");
    assert!(updated_user.verification_token_expires_at.is_none(), "Verification token expiration should be removed");
}

#[actix_rt::test]
async fn test_email_verification_with_invalid_token() {
    dotenv::from_filename(".env.test").ok();

    let pool = web::Data::new(get_test_db_pool().await);
    clean_database(pool.get_ref()).await;

    let mut app = setup_test_app(pool.clone()).await;

    let invalid_token = "invalid_token";

    let req = test::TestRequest::get()
        .uri(&format!("/verify?token={}", invalid_token))
        .to_request();

    let resp = test::call_service(&mut app, req).await;

    println!("Response status: {:?}", resp.status());
    println!("Response headers: {:?}", resp.headers());

    let status = resp.status();
    let body = test::read_body(resp).await;
    println!("Response body: {:?}", String::from_utf8_lossy(&body));

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(String::from_utf8_lossy(&body), "Invalid token format");
}

    */
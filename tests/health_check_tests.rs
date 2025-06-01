use actix_web::{test, App};
use oxidizedoasis_websands::api::routes::route_config::configure_all;
use oxidizedoasis_websands::infrastructure::database::connection::create_pool;
use serde_json::Value;

#[actix_rt::test]
async fn test_health_check_endpoint() {
    // Load .env file for database URL and other configurations
    dotenv::dotenv().ok();

    let db_pool = create_pool().await.expect("Failed to create database pool for test");

    let mut app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(db_pool.clone()))
            .configure(configure_all)
    ).await;

    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success(), "Response status should be 2xx");

    let body: Value = test::read_body_json(resp).await;

    assert_eq!(body["status"], "OK", "Status should be OK");
    assert!(body["version"].as_str().is_some(), "Version should be a string");
    assert!(body["uptime"].as_str().is_some(), "Uptime should be a string");

    // Check database status specifically
    // This implicitly tests database connectivity if the main health_check logic includes a ping
    assert_eq!(body["database_status"], "OK", "Database status should be OK");
}

#[actix_rt::test]
async fn test_database_connectivity_via_health_check() {
    // Load .env file
    dotenv::dotenv().ok();

    let db_pool = create_pool().await.expect("Failed to create database pool for test");

    // Test a simple query
    let result = sqlx::query("SELECT 1 as id")
        .fetch_one(&db_pool)
        .await;

    assert!(result.is_ok(), "Database query failed: {:?}", result.err());
    // You could also check the value if needed:
    // use sqlx::Row;
    // let row = result.unwrap();
    // assert_eq!(row.get::<i32, _>("id"), 1);

    // Now, ensure the health check reports the DB as OK
    let mut app = test::init_service(
        App::new()
            .app_data(actix_web::web::Data::new(db_pool.clone()))
            .configure(configure_all)
    ).await;

    let req = test::TestRequest::get().uri("/api/health").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert!(resp.status().is_success(), "Health check response status should be 2xx");

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["database_status"], "OK", "Health check should report database_status as OK");
}

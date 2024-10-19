use sqlx::PgPool;
use log::{info, error};

pub async fn run_migrations(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    info!("Running database migrations");
    match sqlx::migrate!("./migrations").run(pool).await {
        Ok(_) => {
            info!("Migrations completed successfully");
            Ok(())
        },
        Err(e) => {
            error!("Migration failed: {:?}", e);
            Err(Box::new(e))
        }
    }
}
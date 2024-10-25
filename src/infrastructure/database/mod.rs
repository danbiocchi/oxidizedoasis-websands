mod connection;
mod migrations;


// Re-export commonly used items for easier access
pub use connection::{create_pool, DatabasePool};
pub use migrations::run_migrations;
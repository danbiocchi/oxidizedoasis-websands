pub mod jwt;          // Make `jwt` public so its contents can be accessed externally
pub mod service;

pub use jwt::{create_jwt, validate_jwt, Claims};  // Re-export these items for easier access
pub use service::AuthService;

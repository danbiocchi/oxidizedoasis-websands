pub mod jwt;          // Make `jwt` public so its contents can be accessed externally
pub mod service;

pub use jwt::Claims;  // Re-export only what's needed
pub use service::AuthService;

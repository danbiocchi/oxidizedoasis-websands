pub mod jwt;          // Make `jwt` public so its contents can be accessed externally
pub mod service;
pub mod token_revocation;

pub use jwt::Claims;  // Re-export only what's needed
pub use service::AuthService;
pub use token_revocation::TokenRevocationService;

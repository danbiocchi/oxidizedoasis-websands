pub mod jwt;          // Make `jwt` public so its contents can be accessed externally
pub mod service;
pub mod token_revocation;
pub mod active_token;

  // Re-export only what's needed
pub use service::AuthService;

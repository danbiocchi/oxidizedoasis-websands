// src/core/email/mod.rs
pub mod service; // Made public
pub mod templates; // Also make public if needed by other modules, or keep private if not

pub use service::EmailServiceTrait;
// If MockEmailService is to be used directly, it might need to be re-exported here under cfg(test)
// e.g., #[cfg(test)] pub use service::mock::MockEmailService;
// However, direct path import should work if `service` module is public.

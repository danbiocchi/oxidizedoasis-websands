pub mod model;
pub mod repository; // Make repository module public to access its items
pub mod service;    // Make service module public if needed elsewhere, or keep mod

pub use model::User;
pub use repository::{UserRepository, UserRepositoryTrait}; // Re-export the trait
#[cfg(test)] // The mock is only needed for tests
pub use repository::MockUserRepositoryTrait; // Re-export the mock
pub use service::UserService;

// frontend/src/pages/mod.rs
pub(crate) mod home;
mod about;
mod login;
mod dashboard;
mod register;
mod email_verified;
mod registration_complete;

pub use home::Home;
pub use about::About;
pub use login::Login;
pub use dashboard::Dashboard;
pub use register::Register;
pub use email_verified::EmailVerified;
pub use registration_complete::RegistrationComplete;


// frontend/src/pages/mod.rs
pub(crate) mod home;
mod about;
mod login;
mod dashboard;
mod register;
mod email_verified;
mod registration_complete;
mod not_found;
mod password_reset_request;
mod password_reset_verify;
mod password_reset_new;

pub use home::Home;
pub use about::About;
pub use login::Login;
pub use register::Register;
pub use email_verified::EmailVerified;
pub use registration_complete::RegistrationComplete;
pub use dashboard::Dashboard;
pub use password_reset_request::PasswordResetRequest;
pub use password_reset_verify::PasswordResetVerify;
pub use password_reset_new::PasswordResetNew;

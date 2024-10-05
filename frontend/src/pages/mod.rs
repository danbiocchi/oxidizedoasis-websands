// frontend/src/pages/mod.rs
pub(crate) mod home;
mod about;
mod login;
mod dashboard;

pub use home::Home;
pub use about::About;
pub use login::Login;
pub use dashboard::Dashboard;
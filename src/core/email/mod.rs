// src/core/email/mod.rs
mod service;
mod templates;

pub use service::{EmailService, EmailServiceTrait};
pub use templates::EmailTemplate;
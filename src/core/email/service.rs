use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;
use std::error::Error;
use crate::core::email::templates::EmailTemplate;
use mockall::automock; // Keep one import
// use mockall; // Remove duplicate
use async_trait::async_trait; // Import async_trait

// Ensure automock is imported (already done by the line above)

#[automock] // Restored automock
#[async_trait] 
pub trait EmailServiceTrait: Send + Sync {
    async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
    // clone_box might not be needed if services are Arc<dyn Trait> from the start,
    // but if it's part of the API, it needs to be mockable or handled.
    // For now, let's keep it simple and focus on the async methods.
    // If clone_box is essential, it might need to be non-async or handled differently for mocking.
    // Let's comment it out for now to simplify mocking the async methods.
    // fn clone_box(&self) -> Arc<dyn EmailServiceTrait>;
}

#[derive(Clone)]
pub struct EmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_server: String,
    from_email: String,
    app_name: String,
    email_from_name: String,
    email_verification_subject: String,
    email_password_reset_subject: String,
}

impl EmailService {
    pub fn new() -> Self {
        EmailService {
            smtp_username: std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            smtp_server: std::env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            from_email: std::env::var("FROM_EMAIL").expect("FROM_EMAIL must be set"),
            app_name: std::env::var("APP_NAME").expect("APP_NAME must be set"),
            email_from_name: std::env::var("EMAIL_FROM_NAME").expect("EMAIL_FROM_NAME must be set"),
            email_verification_subject: std::env::var("EMAIL_VERIFICATION_SUBJECT").expect("EMAIL_VERIFICATION_SUBJECT must be set"),
            email_password_reset_subject: std::env::var("EMAIL_PASSWORD_RESET_SUBJECT").expect("EMAIL_PASSWORD_RESET_SUBJECT must be set"),
        }
    }

    fn get_base_url() -> String {
        std::env::var("ENVIRONMENT")
            .map(|env| {
                if env == "production" {
                    std::env::var("PRODUCTION_URL").expect("PRODUCTION_URL must be set")
                } else {
                    std::env::var("DEVELOPMENT_URL").expect("DEVELOPMENT_URL must be set")
                }
            })
            .expect("ENVIRONMENT must be set")
    }
}

#[async_trait] 
impl EmailServiceTrait for EmailService {
    async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let base_url = Self::get_base_url();
        let verification_url = format!("{}/users/verify?token={}", base_url, verification_token);

        let template = EmailTemplate::Verification {
            verification_url,
            app_name: self.app_name.clone(),
        };

        let email_body = template.render(); // Ensure this is Send + Sync or handle appropriately

        let from_address = format!("{} <{}>", self.email_from_name, self.from_email)
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let to_address = to_email // Keep only one definition
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        let email_result = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject(&self.email_verification_subject)
            .header(ContentType::TEXT_HTML)
            .body(lettre::message::Body::new(email_body)); // Use Body::new()
        
        let email = email_result
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?; // Map error and use '?'

        let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

        let mailer = SmtpTransport::relay(&self.smtp_server).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
            .credentials(creds)
            .build();

        // SmtpTransport::send is blocking, consider wrapping in spawn_blocking for true async
        // For now, assume it's acceptable for this service's async signature.
        match mailer.send(&email) { // Use the 'email' variable which is now correctly typed and assigned
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Could not send email: {:?}", e);
                Err(Box::new(e) as Box<dyn Error + Send + Sync>)
            }
        }
    }

    async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
        let base_url = Self::get_base_url();
        let reset_url = format!("{}/password-reset/verify?token={}", base_url, reset_token);

        let template = EmailTemplate::PasswordReset {
            reset_url,
            app_name: self.app_name.clone(),
        };
        
        let email_body = template.render();

        let from_address_reset = format!("{} <{}>", self.email_from_name, self.from_email)
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let to_address_reset = to_email // Keep only one definition
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        let email_result = Message::builder()
            .from(from_address_reset)
            .to(to_address_reset)
            .subject(&self.email_password_reset_subject)
            .header(ContentType::TEXT_HTML)
            .body(lettre::message::Body::new(email_body)); // Use Body::new()

        let email = email_result
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?; // Map error and use '?'

        let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

        let mailer = SmtpTransport::relay(&self.smtp_server).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
            .credentials(creds)
            .build();

        match mailer.send(&email) { // Use the 'email' variable
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Could not send password reset email: {:?}", e);
                Err(Box::new(e) as Box<dyn Error + Send + Sync>)
            }
        }
    }

    // fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
    //     Arc::new(self.clone())
    // }
}

// The manual mock module below is now redundant if #[automock] is used and working.
// It can be removed if MockEmailServiceTrait (generated by automock) is preferred.
// For now, let's comment it out to avoid potential conflicts.
// Update: Trying to make mock module always visible, contents cfg(test)
pub mod mock { // Module is now unconditionally public
    #[cfg(test)] // Items within are for test builds
    use super::*;
    #[cfg(test)]
    use std::sync::{Arc, Mutex}; // Ensure Arc is imported here
    use async_trait::async_trait;

    #[cfg(test)]
    #[derive(Clone)]
    pub struct MockEmailService {
        sent_emails: Arc<Mutex<Vec<String>>>,
        pub should_succeed: Arc<Mutex<bool>>,
    }

    #[cfg(test)]
    impl MockEmailService {
        pub fn new() -> Self {
            Self {
                sent_emails: Arc::new(Mutex::new(Vec::new())),
                should_succeed: Arc::new(Mutex::new(true)),
            }
        }

        pub fn get_sent_emails(&self) -> Vec<String> {
            self.sent_emails.lock().unwrap().clone()
        }
        
        pub fn set_should_succeed(&self, succeed: bool) {
            let mut guard = self.should_succeed.lock().unwrap();
            *guard = succeed;
        }
    }
    
    #[cfg(test)]
    #[async_trait]
    impl EmailServiceTrait for MockEmailService {
        async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
            if !*self.should_succeed.lock().unwrap() {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Simulated email failure by mock")) as Box<dyn Error + Send + Sync>);
            }
            self.sent_emails.lock().unwrap().push(format!("Verification email to {} with token {}", to_email, verification_token));
            Ok(())
        }

        async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
            if !*self.should_succeed.lock().unwrap() {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Simulated email failure by mock")) as Box<dyn Error + Send + Sync>);
            }
            self.sent_emails.lock().unwrap().push(format!("Password reset email to {} with token {}", to_email, reset_token));
            Ok(())
        }
    }
}
// */ // Ensure this is commented out if not used, or fully uncommented if used.
// For now, assuming #[automock] is the primary strategy, so keeping this manual mock commented.
// If #[automock] fails, this manual mock is the fallback.
// The previous step commented out the /* ... */ block. Let's ensure it stays commented if automock is active.
// The current file content shows it commented, so this diff will effectively uncomment it and apply cfg(test) internally.

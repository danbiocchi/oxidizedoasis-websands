use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;
use std::error::Error;
use std::sync::Arc;
use crate::core::email::templates::EmailTemplate;

pub trait EmailServiceTrait: Send + Sync {
    fn send_verification_email<'a>(&'a self, to_email: &'a str, verification_token: &'a str) 
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>>;
    fn send_password_reset_email<'a>(&'a self, to_email: &'a str, reset_token: &'a str)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>>;
    fn clone_box(&self) -> Arc<dyn EmailServiceTrait>;
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

impl EmailServiceTrait for EmailService {
    fn send_verification_email<'a>(&'a self, to_email: &'a str, verification_token: &'a str) 
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>> {
        Box::pin(async move {
            let base_url = Self::get_base_url();
            let verification_url = format!("{}/users/verify?token={}", base_url, verification_token);

            let template = EmailTemplate::Verification {
                verification_url,
                app_name: self.app_name.clone(),
            };

            let email = Message::builder()
                .from(format!("{} <{}>", self.email_from_name, self.from_email).parse()?)
                .to(to_email.parse()?)
                .subject(&self.email_verification_subject)
                .header(ContentType::TEXT_HTML)
                .body(template.render())?;

            let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

            let mailer = SmtpTransport::relay(&self.smtp_server)?
                .credentials(creds)
                .build();

            match mailer.send(&email) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Could not send email: {:?}", e);
                    Err(Box::new(e) as Box<dyn Error>)  // Add explicit conversion here
                }
            }
        })
    }

    fn send_password_reset_email<'a>(&'a self, to_email: &'a str, reset_token: &'a str)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>> {
        Box::pin(async move {
            let base_url = Self::get_base_url();
            let reset_url = format!("{}/password-reset/verify?token={}", base_url, reset_token);

            let template = EmailTemplate::PasswordReset {
                reset_url,
                app_name: self.app_name.clone(),
            };

            let email = Message::builder()
                .from(format!("{} <{}>", self.email_from_name, self.from_email).parse()?)
                .to(to_email.parse()?)
                .subject(&self.email_password_reset_subject)
                .header(ContentType::TEXT_HTML)
                .body(template.render())?;

            let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

            let mailer = SmtpTransport::relay(&self.smtp_server)?
                .credentials(creds)
                .build();

            match mailer.send(&email) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Could not send password reset email: {:?}", e);
                    Err(Box::new(e) as Box<dyn Error>)
                }
            }
        })
    }

    fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    pub struct MockEmailService {
        sent_emails: Arc<Mutex<Vec<String>>>,
    }

    impl MockEmailService {
        pub fn new() -> Self {
            Self {
                sent_emails: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn get_sent_emails(&self) -> Vec<String> {
            self.sent_emails.lock().unwrap().clone()
        }
    }

    impl EmailServiceTrait for MockEmailService {
        fn send_verification_email<'a>(&'a self, to_email: &'a str, verification_token: &'a str)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>> {
            let emails = self.sent_emails.clone();
            Box::pin(async move {
                emails.lock().unwrap().push(format!("Verification email to {} with token {}", to_email, verification_token));
                Ok(())
            })
        }

        fn send_password_reset_email<'a>(&'a self, to_email: &'a str, reset_token: &'a str)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn Error>>> + Send + 'a>> {
            let emails = self.sent_emails.clone();
            Box::pin(async move {
                emails.lock().unwrap().push(format!("Password reset email to {} with token {}", to_email, reset_token));
                Ok(())
            })
        }

        fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
            Arc::new(Self {
                sent_emails: self.sent_emails.clone(),
            })
        }
    }
}

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;
use std::error::Error;
use std::sync::Arc;
use crate::core::email::templates::EmailTemplate;

pub trait EmailServiceTrait: Send + Sync {
    fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>>;
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
    fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>> {
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
                Err(Box::new(e))
            }
        }
    }

    fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
        Arc::new(self.clone())
    }
}
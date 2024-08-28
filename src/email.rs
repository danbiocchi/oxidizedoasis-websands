use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::error;

pub struct EmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_server: String,
    from_email: String,
}

impl EmailService {
    pub fn new() -> Self {
        EmailService {
            smtp_username: std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            smtp_server: std::env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            from_email: std::env::var("FROM_EMAIL").expect("FROM_EMAIL must be set"),
        }
    }

    pub fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let email = Message::builder()
            .from(self.from_email.parse()?)
            .to(to_email.parse()?)
            .subject("Verify Your Email")
            .body(format!("Click the following link to verify your email: http://localhost:8080/verify-email?token={}", verification_token))?;

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
}
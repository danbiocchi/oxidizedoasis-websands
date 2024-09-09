use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;
use std::error::Error;
#[allow(dead_code)]
pub trait EmailServiceTrait: Send + Sync {
    fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>>;
    fn clone_box(&self) -> Box<dyn EmailServiceTrait>;
}

#[derive(Clone)]
pub struct RealEmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_server: String,
    from_email: String,
}

impl RealEmailService {
    pub fn new() -> Self {
        RealEmailService {
            smtp_username: std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            smtp_server: std::env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            from_email: std::env::var("FROM_EMAIL").expect("FROM_EMAIL must be set"),
        }
    }
}

impl EmailServiceTrait for RealEmailService {
    fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>> {
        let base_url = std::env::var("ENVIRONMENT")
            .map(|env| {
                if env == "production" {
                    std::env::var("PRODUCTION_URL").expect("PRODUCTION_URL must be set")
                } else {
                    std::env::var("DEVELOPMENT_URL").expect("DEVELOPMENT_URL must be set")
                }
            })
            .expect("ENVIRONMENT must be set");

        let verification_url = format!("{}/users/verify?token={}", base_url, verification_token);

        let email_body = format!(
            r#"
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9; border-radius: 5px;">
                    <h1 style="color: #3498db;">Verify Your Email</h1>
                    <p>Thank you for signing up with OxidizedOasis! Please click the button below to verify your email address:</p>
                    <p style="text-align: center;">
                        <a href="{0}" style="display: inline-block; padding: 10px 20px; background-color: #3498db; color: #ffffff; text-decoration: none; border-radius: 5px;">Verify Email</a>
                    </p>
                    <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                    <p><a href="{0}">{0}</a></p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't sign up for an account, you can safely ignore this email.</p>
                </div>
            </body>
            </html>
            "#,
            verification_url
        );

        let email = Message::builder()
            .from(self.from_email.parse()?)
            .to(to_email.parse()?)
            .subject("Verify Your Email - OxidizedOasis")
            .header(ContentType::TEXT_HTML)
            .body(email_body)?;

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

    fn clone_box(&self) -> Box<dyn EmailServiceTrait> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    pub struct MockEmailService {
        pub sent_emails: Mutex<Vec<(String, String)>>,
    }
    #[allow(dead_code)]
    impl MockEmailService {
        pub fn new() -> Self {
            MockEmailService {
                sent_emails: Mutex::new(Vec::new()),
            }
        }
    }

    impl Clone for MockEmailService {
        fn clone(&self) -> Self {
            MockEmailService {
                sent_emails: Mutex::new(self.sent_emails.lock().unwrap().clone()),
            }
        }
    }
    #[allow(dead_code)]
    impl EmailServiceTrait for MockEmailService {
        fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>> {
            self.sent_emails.lock().unwrap().push((to_email.to_string(), verification_token.to_string()));
            Ok(())
        }
        #[allow(dead_code)]
        fn clone_box(&self) -> Box<dyn EmailServiceTrait> {
            Box::new(self.clone())
        }
    }
}
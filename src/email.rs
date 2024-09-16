use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;
use std::error::Error;
use std::sync::Arc;

#[allow(dead_code)]
pub trait EmailServiceTrait: Send + Sync {
    fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn Error>>;
    fn clone_box(&self) -> Arc<dyn EmailServiceTrait>;
}

#[derive(Clone)]
pub struct RealEmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_server: String,
    from_email: String,
    app_name: String,
    email_from_name: String,
    email_verification_subject: String,
}

impl RealEmailService {
    pub fn new() -> Self {
        RealEmailService {
            smtp_username: std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            smtp_server: std::env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            from_email: std::env::var("FROM_EMAIL").expect("FROM_EMAIL must be set"),
            app_name: std::env::var("APP_NAME").expect("APP_NAME must be set"),
            email_from_name: std::env::var("EMAIL_FROM_NAME").expect("EMAIL_FROM_NAME must be set"),
            email_verification_subject: std::env::var("EMAIL_VERIFICATION_SUBJECT").expect("EMAIL_VERIFICATION_SUBJECT must be set"),
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
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f0f0f0; margin: 0; padding: 0;">
                <div style="max-width: 600px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h1 style="color: #3498db; text-align: center; margin-bottom: 20px;">Verify Your Email</h1>
                    <p style="margin-bottom: 20px;">Thank you for signing up with {1}! Please click the button below to verify your email address:</p>
                    <div style="text-align: center; margin-bottom: 20px;">
                        <a href="{0}" style="display: inline-block; padding: 10px 20px; background-color: #3498db; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify Email</a>
                    </div>
                    <p style="margin-bottom: 10px;">If the button doesn't work, you can copy and paste the following link into your browser:</p>
                    <p style="background-color: #f8f8f8; padding: 10px; border-radius: 5px; word-break: break-all;"><a href="{0}" style="color: #3498db; text-decoration: none;">{0}</a></p>
                    <p style="margin-top: 20px; font-size: 0.9em; color: #777;">This link will expire in 24 hours.</p>
                    <p style="font-size: 0.9em; color: #777;">If you didn't sign up for an account, you can safely ignore this email.</p>
                </div>
            </body>
            </html>
            </html>
            "#,
            verification_url,
            self.app_name
        );

        let email = Message::builder()
            .from(format!("{} <{}>", self.email_from_name, self.from_email).parse()?)
            .to(to_email.parse()?)
            .subject(&self.email_verification_subject)
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

    fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
        Arc::new(self.clone())
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
        fn clone_box(&self) -> Arc<dyn EmailServiceTrait> {
            Arc::new(self.clone())
        }
    }
}
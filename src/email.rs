use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use log::error;

/// Struct to handle email-related operations
pub struct EmailService {
    smtp_username: String,
    smtp_password: String,
    smtp_server: String,
    from_email: String,
}

impl EmailService {
    /// Create a new EmailService instance
    pub fn new() -> Self {
        EmailService {
            smtp_username: std::env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
            smtp_password: std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
            smtp_server: std::env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
            from_email: std::env::var("FROM_EMAIL").expect("FROM_EMAIL must be set"),
        }
    }

    /// Send a verification email to the user
    ///
    /// # Arguments
    /// * `to_email` - The recipient's email address
    /// * `verification_token` - The verification token to be included in the email
    ///
    /// # Returns
    /// * `Result<(), Box<dyn std::error::Error>>` - Ok if email sent successfully, Err otherwise
    pub fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let email_body = format!(
            r#"
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9; border-radius: 5px;">
                    <h1 style="color: #3498db;">Verify Your Email</h1>
                    <p>Thank you for signing up with OxidizedOasis! Please click the button below to verify your email address:</p>
                    <p style="text-align: center;">
                        <a href="http://localhost:8080/users/verify?token={}" style="display: inline-block; padding: 10px 20px; background-color: #3498db; color: #ffffff; text-decoration: none; border-radius: 5px;">Verify Email</a>
                    </p>
                    <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                    <p><a href="http://localhost:8080/users/verify?token={}">http://localhost:8080/users/verify?token={}</a></p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't sign up for an account, you can safely ignore this email.</p>
                </div>
            </body>
            </html>
            "#,
            verification_token, verification_token, verification_token
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
}
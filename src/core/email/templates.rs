pub enum EmailTemplate {
    Verification {
        verification_url: String,
        app_name: String,
    },
    PasswordReset {
        reset_url: String,
        app_name: String,
    },
}

impl EmailTemplate {
    pub fn render(&self) -> String {
        match self {
            EmailTemplate::Verification { verification_url, app_name } => {
                format!(
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
                    "#,
                    verification_url,
                    app_name
                )
            }
            EmailTemplate::PasswordReset { reset_url, app_name } => {
                format!(
                    r#"
                    <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f0f0f0; margin: 0; padding: 0;">
                        <div style="max-width: 600px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                            <h1 style="color: #3498db; text-align: center; margin-bottom: 20px;">Reset Your Password</h1>
                            <p style="margin-bottom: 20px;">We received a request to reset your {1} password. Click the button below to choose a new password:</p>
                            <div style="text-align: center; margin-bottom: 20px;">
                                <a href="{0}" style="display: inline-block; padding: 10px 20px; background-color: #3498db; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
                            </div>
                            <p style="margin-bottom: 10px;">If the button doesn't work, you can copy and paste the following link into your browser:</p>
                            <p style="background-color: #f8f8f8; padding: 10px; border-radius: 5px; word-break: break-all;"><a href="{0}" style="color: #3498db; text-decoration: none;">{0}</a></p>
                            <p style="margin-top: 20px; font-size: 0.9em; color: #777;">This link will expire in 1 hour for security reasons.</p>
                            <p style="font-size: 0.9em; color: #777;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
                        </div>
                    </body>
                    </html>
                    "#,
                    reset_url,
                    app_name
                )
            }
        }
    }
}

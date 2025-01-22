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
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                    </head>
                    <body style="margin: 0; padding: 0; background-color: hsl(210, 25%, 8%); color: hsl(0, 0%, 100%); font-family: Arial, sans-serif;">
                        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: hsl(210, 25%, 8%);">
                            <tr>
                                <td align="center" style="padding: 40px 0;">
                                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: hsl(210, 18%, 12%); border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
                                        <tr>
                                            <td align="center" style="padding: 40px 40px 30px 40px;">
                                                <svg width="200" height="100" viewBox="0 0 200 100">
                                                    <g transform="translate(40,0)">
                                                        <rect fill="hsl(221, 83%, 53%)" x="0" y="20" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="20" y="10" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="40" y="30" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="60" y="15" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="80" y="25" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="100" y="5" width="10" height="10"/>
                                                    </g>
                                                    <text x="100" y="80" text-anchor="middle" 
                                                          style="font-family: Arial; font-size: 16px; fill: hsl(221, 83%, 53%); letter-spacing: 2px;">{1}</text>
                                                </svg>
                                                <h1 style="color: hsl(221, 83%, 53%); margin: 20px 0; font-size: 24px; font-weight: normal;">Verify Your Email</h1>
                                                <p style="color: hsl(0, 0%, 100%); margin: 0 0 30px 0; line-height: 24px;">Thank you for signing up with {1}! Please click the button below to verify your email address:</p>
                                                <table cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                                    <tr>
                                                        <td style="background-color: hsl(221, 83%, 53%); border-radius: 4px;">
                                                            <a href="{0}" style="display: block; padding: 15px 30px; color: hsl(210, 25%, 8%); text-decoration: none; font-weight: bold;">Verify Email</a>
                                                        </td>
                                                    </tr>
                                                </table>
                                                <p style="color: hsl(0, 0%, 80%); margin: 0 0 10px 0; font-size: 14px;">If the button doesn't work, you can copy and paste the following link into your browser:</p>
                                                <p style="background-color: hsl(210, 12%, 19%); padding: 15px; border-radius: 4px; word-break: break-all; margin: 0 0 20px 0;"><a href="{0}" style="color: hsl(221, 83%, 53%); text-decoration: none;">{0}</a></p>
                                                <p style="color: hsl(0, 0%, 60%); margin: 20px 0 0 0; font-size: 14px;">This link will expire in 24 hours.</p>
                                                <p style="color: hsl(0, 0%, 60%); margin: 10px 0 0 0; font-size: 14px;">If you didn't sign up for an account, you can safely ignore this email.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
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
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="utf-8">
                    </head>
                    <body style="margin: 0; padding: 0; background-color: hsl(210, 25%, 8%); color: hsl(0, 0%, 100%); font-family: Arial, sans-serif;">
                        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: hsl(210, 25%, 8%);">
                            <tr>
                                <td align="center" style="padding: 40px 0;">
                                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: hsl(210, 18%, 12%); border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
                                        <tr>
                                            <td align="center" style="padding: 40px 40px 30px 40px;">
                                                <svg width="200" height="100" viewBox="0 0 200 100">
                                                    <g transform="translate(40,0)">
                                                        <rect fill="hsl(221, 83%, 53%)" x="0" y="20" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="20" y="10" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="40" y="30" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="60" y="15" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="80" y="25" width="10" height="10"/>
                                                        <rect fill="hsl(221, 83%, 53%)" x="100" y="5" width="10" height="10"/>
                                                    </g>
                                                    <text x="100" y="80" text-anchor="middle" 
                                                          style="font-family: Arial; font-size: 16px; fill: hsl(221, 83%, 53%); letter-spacing: 2px;">{1}</text>
                                                </svg>
                                                
                                                <h1 style="color: hsl(221, 83%, 53%); margin: 20px 0; font-size: 24px; font-weight: normal;">Reset Your Password</h1>
                                                <p style="color: hsl(0, 0%, 100%); margin: 0 0 30px 0; line-height: 24px;">We received a request to reset your {1} password. Click the button below to choose a new password:</p>
                                                <table cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                                                    <tr>
                                                        <td style="background-color: hsl(221, 83%, 53%); border-radius: 4px;">
                                                            <a href="{0}" style="display: block; padding: 15px 30px; color: hsl(210, 25%, 8%); text-decoration: none; font-weight: bold;">Reset Password</a>
                                                        </td>
                                                    </tr>
                                                </table>
                                                <p style="color: hsl(0, 0%, 80%); margin: 0 0 10px 0; font-size: 14px;">If the button doesn't work, you can copy and paste the following link into your browser:</p>
                                                <p style="background-color: hsl(210, 12%, 19%); padding: 15px; border-radius: 4px; word-break: break-all; margin: 0 0 20px 0;"><a href="{0}" style="color: hsl(221, 83%, 53%); text-decoration: none;">{0}</a></p>
                                                <p style="color: hsl(0, 0%, 60%); margin: 20px 0 0 0; font-size: 14px;">This link will expire in 1 hour for security reasons.</p>
                                                <p style="color: hsl(0, 0%, 60%); margin: 10px 0 0 0; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                        </table>
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

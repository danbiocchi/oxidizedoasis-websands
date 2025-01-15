use yew::prelude::*;

/// Context for managing password reset token
#[derive(Clone, PartialEq)]
pub struct ResetTokenContext {
    pub token: String,
    pub set_token: Callback<String>,
}

impl ResetTokenContext {
    pub fn new(token: String, set_token: Callback<String>) -> Self {
        Self {
            token,
            set_token,
        }
    }
}

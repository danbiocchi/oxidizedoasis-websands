// frontend/src/services/auth_context.rs
use yew::prelude::*;

#[derive(Clone, PartialEq)]
pub struct AuthContext {
    pub is_authenticated: bool,
    pub set_auth: Callback<bool>,
}

impl AuthContext {
    pub fn new(is_authenticated: bool, set_auth: Callback<bool>) -> Self {
        Self {
            is_authenticated,
            set_auth,
        }
    }
}
use yew::prelude::*;

#[derive(Clone, PartialEq)]
pub struct ConfettiContext {
    pub is_active: bool,
    pub set_active: Callback<bool>,
}

impl ConfettiContext {
    pub fn new(is_active: bool, set_active: Callback<bool>) -> Self {
        Self {
            is_active,
            set_active,
        }
    }
}
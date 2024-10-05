use gloo::storage::{LocalStorage, Storage};

const TOKEN_KEY: &str = "auth_token";

pub fn set_token(token: &str) {
    LocalStorage::set(TOKEN_KEY, token).expect("failed to set token");
}

pub fn get_token() -> Option<String> {
    LocalStorage::get(TOKEN_KEY).ok()
}

pub fn remove_token() {
    LocalStorage::delete(TOKEN_KEY);
}

pub fn is_authenticated() -> bool {
    get_token().is_some()
}

#[warn(dead_code)]
pub fn logout() {
    remove_token();
    // You might want to redirect to the login page or update app state here
}


use gloo::storage::{LocalStorage, Storage};
use gloo::console::log;
use wasm_bindgen_futures::spawn_local;
use gloo::net::http::Request;
use serde_json::json;

const ACCESS_TOKEN_KEY: &str = "access_token";
const REFRESH_TOKEN_KEY: &str = "refresh_token";

// Store access token
pub fn set_access_token(token: &str) {
    LocalStorage::set(ACCESS_TOKEN_KEY, token).expect("failed to set access token");
}

// Get access token
pub fn get_access_token() -> Option<String> {
    LocalStorage::get(ACCESS_TOKEN_KEY).ok()
}

// Store refresh token
pub fn set_refresh_token(token: &str) {
    LocalStorage::set(REFRESH_TOKEN_KEY, token).expect("failed to set refresh token");
}

// Get refresh token
pub fn get_refresh_token() -> Option<String> {
    LocalStorage::get(REFRESH_TOKEN_KEY).ok()
}

// Remove both tokens
pub fn remove_tokens() {
    LocalStorage::delete(ACCESS_TOKEN_KEY);
    LocalStorage::delete(REFRESH_TOKEN_KEY);
}

// Check if user is authenticated (has access token)
pub fn is_authenticated() -> bool {
    get_access_token().is_some()
}

// Store both tokens from a token pair
pub fn set_token_pair(access_token: &str, refresh_token: &str) {
    set_access_token(access_token);
    set_refresh_token(refresh_token);
}

// Get current token (for API calls)
pub fn get_auth_token() -> Option<String> {
    get_access_token()
}

// Logout - revoke tokens on server and remove from storage
pub fn logout() {
    // If we have an access token, try to revoke it on the server
    if let Some(access_token) = get_access_token() {
        // Get refresh token if available
        let refresh_token = get_refresh_token();
        
        // Call logout API to revoke tokens
        spawn_local(async move {
            let mut request = Request::post("/users/logout")
                .header("Authorization", &format!("Bearer {}", access_token));
            
            // Prepare the request body and send
            let body = if let Some(refresh_token) = refresh_token {
                json!({
                    "refresh_token": refresh_token
                })
            } else {
                json!({})
            };
            
            // Create a new request with the body
            let response = Request::post("/users/logout")
                .header("Authorization", &format!("Bearer {}", access_token))
                .json(&body)
                .expect("Failed to build request body")
                .send()
                .await;
                
            match response {
                Ok(_) => log!("Logout successful"),
                Err(e) => log!("Logout error:", e.to_string()),
            }
        });
    }
    
    // Remove tokens from local storage
    remove_tokens();
}

// Refresh access token using refresh token
pub async fn refresh_access_token() -> Result<(), String> {
    if let Some(refresh_token) = get_refresh_token() {
        log!("Refreshing tokens using refresh token");
        match Request::post("/users/refresh")
            .json(&json!({
                "token": refresh_token
            }))
            .expect("Failed to build request")
            .send()
            .await
        {
            Ok(response) => {
                match response.json::<serde_json::Value>().await {
                    Ok(data) => {
                        // Extract both tokens from the response
                        let data_obj = data.get("data");
                        let new_access_token = data_obj.and_then(|d| d.get("access_token")).and_then(|t| t.as_str());
                        let new_refresh_token = data_obj.and_then(|d| d.get("refresh_token")).and_then(|t| t.as_str());
                        
                        if let (Some(access_token), Some(refresh_token)) = (new_access_token, new_refresh_token) {
                            // Store both new tokens
                            log!("Received new token pair, updating storage");
                            set_token_pair(access_token, refresh_token);
                            Ok(())
                        } else {
                            log!("Invalid token response format");
                            Err("Invalid response format: missing tokens".to_string())
                        }
                    },
                    Err(e) => Err(format!("Failed to parse response: {}", e))
                }
            },
            Err(e) => Err(format!("Network error: {}", e))
        }
    } else {
        Err("No refresh token available".to_string())
    }
}

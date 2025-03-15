use gloo::storage::{LocalStorage, Storage};
use gloo::console::log;
use wasm_bindgen_futures::spawn_local;
use gloo::timers::callback::Timeout;
use gloo::net::http::Request;
use serde_json::json;

use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::string::FromUtf8Error;

const CSRF_TOKEN_KEY: &str = "csrf_token";
const AUTH_TOKEN_KEY: &str = "auth_token";
const TOKEN_EXPIRY_KEY: &str = "token_expiry";

// Singleton for token refresh timer
thread_local! {
    static TOKEN_REFRESH_TIMER: RefCell<Option<Timeout>> = RefCell::new(None);
}

#[derive(Debug, Deserialize, Serialize)]
struct JwtClaims {
    exp: u64,
    iat: u64,
    sub: String,
    #[serde(rename = "type")]
    token_type: String,
}

// Store CSRF token
pub fn set_csrf_token(token: &str) {
    LocalStorage::set(CSRF_TOKEN_KEY, token).expect("failed to set CSRF token");
}

// Store token expiry time
fn set_token_expiry(expiry: u64) {
    LocalStorage::set(TOKEN_EXPIRY_KEY, expiry).expect("failed to set token expiry");
}

// Get token expiry time
fn get_token_expiry() -> Option<u64> {
    LocalStorage::get(TOKEN_EXPIRY_KEY).ok()
}

// Get CSRF token
pub fn get_csrf_token() -> Option<String> {
    LocalStorage::get(CSRF_TOKEN_KEY).ok()
}

// Get auth token (for backward compatibility)
pub fn get_auth_token() -> Option<String> {
    // For backward compatibility, try to get from localStorage
    LocalStorage::get(AUTH_TOKEN_KEY).ok()
}

// Remove tokens
pub fn remove_tokens() {
    LocalStorage::delete(CSRF_TOKEN_KEY);
    
    // For backward compatibility, also remove old token
    LocalStorage::delete(AUTH_TOKEN_KEY);
    LocalStorage::delete("refresh_token");
    LocalStorage::delete(TOKEN_EXPIRY_KEY);
}

// Check if user is authenticated
// This now relies on the server to check cookies
pub fn is_authenticated() -> bool {
    // We'll check if we have a CSRF token as a proxy for being logged in
    get_csrf_token().is_some()
}

// Setup a timer to refresh the token before it expires
pub fn setup_token_refresh_timer() {
    // Clear any existing timer
    clear_token_refresh_timer();
    
    // Get token expiry time
    if let Some(expiry) = get_token_expiry() {
        let current_time = get_current_timestamp();
        
        // Calculate time until token expires
        if expiry > current_time {
            let time_until_expiry = expiry - current_time;
            
            // Refresh 5 minutes before expiry or halfway through if less than 10 minutes remain
            let refresh_buffer = if time_until_expiry > 600 { 300 } else { time_until_expiry / 2 };
            let refresh_in = if time_until_expiry > refresh_buffer {
                (time_until_expiry - refresh_buffer) * 1000 // Convert to milliseconds
            } else {
                // If token is about to expire, refresh immediately
                0
            };
            
            log!("Setting up token refresh timer for {} seconds from now", refresh_in / 1000);
            
            // Create a new timer
            let timeout = Timeout::new(refresh_in as u32, || {
                log!("Token refresh timer triggered");
                spawn_local(async {
                    match refresh_access_token().await {
                        Ok(_) => {
                            log!("Token refreshed proactively");
                            // Setup the next refresh timer
                            setup_token_refresh_timer();
                        },
                        Err(e) => log!("Proactive token refresh failed: {}", e),
                    }
                });
            });
            
            // Store the timer
            TOKEN_REFRESH_TIMER.with(|cell| *cell.borrow_mut() = Some(timeout));
        }
    }
}

// Clear the token refresh timer
fn clear_token_refresh_timer() {
    TOKEN_REFRESH_TIMER.with(|cell| *cell.borrow_mut() = None);
}

// Get current timestamp in seconds
fn get_current_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            log!("Error getting current timestamp");
            0
        }
    }
}

// Decode JWT token to extract expiration time
fn decode_jwt_expiry(token: &str) -> Option<u64> {
    // Split the token into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        log!("Invalid JWT token format");
        return None;
    }
    
    // Decode the payload (second part)
    let payload = parts[1];
    let decoded = match general_purpose::URL_SAFE_NO_PAD.decode(payload) {
        Ok(decoded) => decoded,
        Err(e) => {
            let error_msg = format!("Failed to decode JWT payload: {}", e);
            log!(error_msg);
            return None;
        }
    };
    
    // Parse the JSON payload
    let payload_str = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(e) => {
            let error_msg = format!("Failed to convert decoded payload to string: {}", e);
            log!(error_msg);
            return None;
        }
    };
    
    // Parse the claims
    match serde_json::from_str::<JwtClaims>(&payload_str) {
        Ok(claims) => Some(claims.exp),
        Err(e) => {
            let error_msg = format!("Failed to parse JWT claims: {}", e);
            log!(error_msg);
            None
        }
    }
}

// Store CSRF token from login response
pub fn store_csrf_token_from_response(data: &serde_json::Value) {
    // Try to get CSRF token from user data structure
    let user_csrf_token = data.get("data")
        .and_then(|d| d.get("user"))
        .and_then(|u| u.get("csrf_token"))
        .and_then(|t| t.as_str());
    
    if let Some(csrf_token) = user_csrf_token {
        set_csrf_token(csrf_token);
        log!("Found CSRF token in user data");
    } else {
        // Also try to get CSRF token from top level of response
        if let Some(csrf_token) = data.get("csrf_token").and_then(|t| t.as_str()) {
            set_csrf_token(csrf_token);
            log!("Found CSRF token at top level");
        }
    }
    
    // Try to extract access token for expiry calculation
    if let Some(access_token) = data.get("data")
        .and_then(|d| d.get("access_token"))
        .and_then(|t| t.as_str()) {
        if let Some(expiry) = decode_jwt_expiry(access_token) {
            set_token_expiry(expiry);
            // Setup proactive token refresh
            setup_token_refresh_timer();
        } else {
            log!("Could not decode token expiry");
        }
    }
}

// Logout - revoke tokens on server and remove from storage
pub fn logout() {
    // Call logout API to revoke tokens
    spawn_local(async move {
        let mut request = Request::post("/api/cookie/users/logout");
        
        // Add CSRF token to request
        if let Some(csrf_token) = get_csrf_token() {
            request = request.header("X-CSRF-Token", &csrf_token);
        }
        
        // Send the request
        let response = request.send().await;
            
        match response {
            Ok(_) => log!("Logout successful"),
            Err(e) => log!("Logout error:", e.to_string()),
        }
    });
    
    // Clear any active refresh timers
    clear_token_refresh_timer();
    
    // Remove CSRF token from local storage
    remove_tokens();
}

// Refresh access token using refresh token
pub async fn refresh_access_token() -> Result<(), String> {
    log!("Refreshing tokens using cookie-based endpoint");

    // Use the cookie-based refresh endpoint
    let mut request = Request::get("/api/cookie/users/refresh");

    // Add CSRF token to request
    if let Some(csrf_token) = get_csrf_token() {
        request = request.header("X-CSRF-Token", &csrf_token);
    }

    match request.send().await {
        Ok(response) => {
            if response.ok() {
                log!("Token refresh successful");

                // Try to extract new CSRF token if available
                match response.json::<serde_json::Value>().await {
                    Ok(data) => {
                        log!("Token refresh response: {}", serde_json::to_string_pretty(&data).unwrap_or_default());
                        
                        let csrf_token = data.get("csrf_token")
                            .and_then(|t| t.as_str())
                            .or_else(|| {
                                // If not found at the top level, try to look in the data structure
                                data.get("data")
                                    .and_then(|d| d.get("user"))
                                    .and_then(|u| u.get("csrf_token"))
                                    .and_then(|t| t.as_str())
                            });
                            
                        if let Some(csrf_token) = csrf_token {
                            set_csrf_token(csrf_token);
                            log!("Updated CSRF token from refresh response");

                            // Try to extract access token for expiry calculation
                            // First try to get token from nested data structure
                            let nested_token = data.get("data")
                                .and_then(|d| d.get("access_token"))
                                .and_then(|t| t.as_str())
;
                                
                            // If not found in nested structure, try top level
                            let top_level_token = data.get("access_token").and_then(|t| t.as_str());
                            
                            // Use whichever token we found
                            if let Some(access_token) = nested_token.or(top_level_token) {
                                if let Some(expiry) = decode_jwt_expiry(access_token) {
                                    set_token_expiry(expiry);
                                    log!("Updated token expiry from refresh response");
                                }
                            }
                        }
                        return Ok(());
                    },
                    Err(_) => return Ok(()) // Still consider it successful even if we can't parse the response
                }
            } else {
                log!("Token refresh failed with status: {}", response.status());
                return Err(format!("Token refresh failed with status: {}", response.status()));
            }
        },
        Err(e) => Err(format!("Network error during token refresh: {}", e))
    }
}

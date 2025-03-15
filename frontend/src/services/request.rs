use gloo::console::log;
use gloo::net::http::{Request, RequestBuilder, Response};
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::pin::Pin;
use crate::services::auth;

/// RequestInterceptor provides a wrapper around the gloo::net::http::Request
/// with automatic token refresh and retry capabilities.
pub struct RequestInterceptor;

impl RequestInterceptor {
    /// Creates a GET request with automatic token refresh and retry capabilities
    pub fn get(url: &str) -> RequestBuilder {
        let mut request = Request::get(url);
        
        // Add CSRF token if available
        if let Some(csrf_token) = auth::get_csrf_token() {
            request = request.header("X-CSRF-Token", &csrf_token);
        }
        
        // Check if token is about to expire and refresh proactively
        Self::check_token_expiration();
        
        request
    }

    /// Creates a POST request with automatic token refresh and retry capabilities
    pub fn post(url: &str) -> RequestBuilder {
        let mut request = Request::post(url);
        
        // Add CSRF token if available
        if let Some(csrf_token) = auth::get_csrf_token() {
            request = request.header("X-CSRF-Token", &csrf_token);
        }
        
        // Check if token is about to expire and refresh proactively
        Self::check_token_expiration();
        
        request
    }

    /// Creates a PUT request with automatic token refresh and retry capabilities
    pub fn put(url: &str) -> RequestBuilder {
        let mut request = Request::put(url);
        
        // Add CSRF token if available
        if let Some(csrf_token) = auth::get_csrf_token() {
            request = request.header("X-CSRF-Token", &csrf_token);
        }
        
        // Check if token is about to expire and refresh proactively
        Self::check_token_expiration();
        
        request
    }

    /// Creates a DELETE request with automatic token refresh and retry capabilities
    pub fn delete(url: &str) -> RequestBuilder {
        let mut request = Request::delete(url);
        
        // Add CSRF token if available
        if let Some(csrf_token) = auth::get_csrf_token() {
            request = request.header("X-CSRF-Token", &csrf_token);
        }
        
        // Check if token is about to expire and refresh proactively
        Self::check_token_expiration();
        
        request
    }
    
    /// Check if token is about to expire and refresh proactively
    fn check_token_expiration() {
        // This will trigger the token refresh timer setup if needed
        auth::setup_token_refresh_timer();
    }
}

/// Extension trait for RequestBuilder to add send_with_retry method
pub trait RequestBuilderExt {
    fn send_with_retry(self) -> Pin<Box<dyn Future<Output = Result<Response, String>>>>;
}

impl RequestBuilderExt for RequestBuilder {
    fn send_with_retry(self) -> Pin<Box<dyn Future<Output = Result<Response, String>>>> {
        Box::pin(async move {
            // First attempt
            let response = self.send().await.map_err(|e| e.to_string())?;
            
            // If unauthorized, try to refresh token and retry
            if response.status() == 401 || response.status() == 403 {
                log!("Request failed with status: {}, attempting token refresh", response.status());
                
                // Try to refresh the token
                match auth::refresh_access_token().await {
                    Ok(()) => {
                        log!("Token refreshed successfully, retrying request");
                        
                        // We need to recreate the request since we can't clone RequestBuilder
                        // Get the URL from the response
                        let url = response.url().to_string();
                        
                        // Create a new request with the same method
                        // We can determine the method from the response status text
                        // This is a bit of a hack, but it works for our purposes
                        let method = if url.contains("logout") {
                            "POST"
                        } else if url.contains("refresh") {
                            "GET"
                        } else {
                            "GET" // Default to GET
                        };
                        
                        let mut new_request = match method {
                            "GET" => Request::get(&url),
                            "POST" => Request::post(&url),
                            "PUT" => Request::put(&url),
                            "DELETE" => Request::delete(&url),
                            _ => Request::get(&url), // Default to GET if unknown
                        };
                        
                        // Add the new CSRF token
                        if let Some(csrf_token) = auth::get_csrf_token() {
                            new_request = new_request.header("X-CSRF-Token", &csrf_token);
                        }
                        
                        // Send the new request
                        let new_response = new_request.send().await.map_err(|e| e.to_string())?;
                        
                        // If still unauthorized after refresh, return error
                        if new_response.status() == 401 || new_response.status() == 403 {
                            return Err("Still unauthorized after token refresh".to_string());
                        }
                        
                        Ok(new_response)
                    },
                    Err(e) => {
                        // Token refresh failed, likely need to re-login
                        auth::remove_tokens();
                        Err(format!("Token refresh failed: {}", e))
                    }
                }
            } else {
                // Return the original response if not unauthorized
                Ok(response)
            }
        })
    }
}
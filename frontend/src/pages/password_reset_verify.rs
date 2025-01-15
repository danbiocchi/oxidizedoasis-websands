use yew::prelude::*;
use yew_router::prelude::*;
use yew_hooks::use_effect_once;
use gloo::net::http::Request;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use crate::routes::Route;
use crate::services::ResetTokenContext;
use web_sys::window;

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

#[function_component(PasswordResetVerify)]
pub fn password_reset_verify() -> Html {
    let error = use_state(|| None::<String>);
    let is_loading = use_state(|| true);
    let navigator = use_navigator().unwrap();
    let verification_key = use_state(String::default);
    let ctx = use_context::<ResetTokenContext>().expect("ResetTokenContext not found");
    let set_token = ctx.set_token.clone();

    // Get token from URL and verify on mount
    {
        let error = error.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();
        let verification_key = verification_key.clone();
        let set_token = set_token.clone();

        use_effect_once(move || {
            let window = window().unwrap();
            let location = window.location();
            let search = location.search().unwrap();
            let params = web_sys::UrlSearchParams::new_with_str(&search).unwrap();
            
            match params.get("token").map(|t| t.trim().to_string()) {
                Some(token) => {
                    // Only verify if we haven't verified this token before
                    let current_key = format!("verified_{}", token);
                    if *verification_key != current_key {
                        verification_key.set(current_key.clone());
                        
                        // Add a small delay to ensure WASM is loaded
                        let future = async move {
                            gloo::timers::future::TimeoutFuture::new(500).await;
                            log!("Starting verification for token:", token.clone());
                            let url = format!("/users/password-reset/verify?token={}", token);
                            log!("Making request to:", url.clone());
                            
                            match Request::get(&url)
                                .send()
                                .await {
                                Ok(resp) => {
                                    log!("Response status:", resp.status());
                                    
                                    match resp.status() {
                                        429 => {
                                            error.set(Some("Too many attempts. Please wait a moment and try again.".to_string()));
                                        }
                                        302 | 200 => {
                                            // Set token in context and navigate
                                            set_token.emit(token.clone());
                                            navigator.push(&Route::PasswordResetNew);
                                        }
                                        _ => {
                                            // Handle error cases
                                            error.set(Some("The password reset link is invalid or has expired".to_string()));
                                        }
                                    }
                                }
                                Err(e) => {
                                    log!("Network error:", e.to_string());
                                    error.set(Some("Network error. Please check your connection and try again.".to_string()));
                                }
                            }
                            is_loading.set(false);
                        };
                        spawn_local(future);
                    } else {
                        is_loading.set(false);
                    }
                }
                None => {
                    log!("No token provided");
                    error.set(Some("Invalid reset link. No token provided.".to_string()));
                    is_loading.set(false);
                }
            }

            || () // Cleanup function
        });
    }

    html! {
        <main class="auth-content">
            <div class="auth-form-container">
                <h1>{"Verifying Reset Link"}</h1>
                if *is_loading {
                    <div class="loading-message">
                        <p>{"Verifying your password reset link..."}</p>
                    </div>
                } else if let Some(err) = &*error {
                    <div class="error-container">
                        <p class="error-message">{err}</p>
                        <div class="auth-links">
                            <Link<Route> to={Route::PasswordResetRequest}>
                                {"Request a new reset link"}
                            </Link<Route>>
                            {" or "}
                            <Link<Route> to={Route::Login}>
                                {"return to login"}
                            </Link<Route>>
                        </div>
                    </div>
                }
            </div>
        </main>
    }
}

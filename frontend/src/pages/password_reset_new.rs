use web_sys::HtmlInputElement;
use yew::prelude::*;
use gloo::net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use yew_router::prelude::*;
use crate::routes::Route;

use crate::services::ResetTokenContext;

/// Form data for password reset
#[derive(Default, Clone, Serialize, Debug)]
struct PasswordResetForm {
    token: String,
    new_password: String,
    confirm_password: String,
}

/// API response structure
#[derive(Deserialize, Debug)]
struct ApiResponse {
    success: bool,
    message: String,
}

/// Component for handling password reset with a new password
#[function_component(PasswordResetNew)]
pub fn password_reset_new() -> Html {
    let ctx = use_context::<ResetTokenContext>().expect("ResetTokenContext not found");
    
    // Initialize form state with token from context
    let form = use_state(|| PasswordResetForm {
        token: ctx.token.clone(),
        new_password: String::new(),
        confirm_password: String::new(),
    });
    let error = use_state(|| None::<String>);
    let success = use_state(|| None::<String>);
    let is_loading = use_state(|| false);
    let navigator = use_navigator().unwrap();
    let password_requirements = use_state(|| vec![false; 5]);

    let onsubmit = {
        let form = form.clone();
        let error = error.clone();
        let success = success.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let form = form.clone();
            let error = error.clone();
            let success = success.clone();
            let is_loading = is_loading.clone();
            let navigator = navigator.clone();

            if form.new_password != form.confirm_password {
                error.set(Some("Passwords do not match".to_string()));
                return;
            }

            is_loading.set(true);
            error.set(None);
            success.set(None);

            spawn_local(async move {
                let response = Request::post("/users/password-reset/reset")
                    .json(&*form)
                    .expect("Failed to build request")
                    .send()
                    .await;

                is_loading.set(false);

                match response {
                    Ok(resp) => {
                        match resp.json::<ApiResponse>().await {
                            Ok(api_resp) => {
                                if api_resp.success {
                                    success.set(Some(api_resp.message.clone()));
                                    // Redirect to login after a short delay
                                    let navigator = navigator.clone();
                                    spawn_local(async move {
                                        gloo::timers::future::TimeoutFuture::new(2000).await;
                                        navigator.push(&Route::Login);
                                    });
                                } else {
                                    error.set(Some(api_resp.message));
                                }
                            },
                            Err(e) => {
                                log!("Failed to parse response:", e.to_string());
                                error.set(Some("An error occurred while processing the response".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        log!("Network error:", e.to_string());
                        error.set(Some("Network error. Please check your connection and try again.".to_string()));
                    }
                }
            });
        })
    };

    let oninput = {
        let form = form.clone();
        let password_requirements = password_requirements.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            let mut new_form = (*form).clone();
            match input.name().as_str() {
                "new_password" => {
                    new_form.new_password = input.value();
                    let password = &new_form.new_password;
                    let mut new_requirements = vec![false; 5];
                    new_requirements[0] = password.len() >= 8;
                    new_requirements[1] = password.chars().any(|c| c.is_uppercase());
                    new_requirements[2] = password.chars().any(|c| c.is_lowercase());
                    new_requirements[3] = password.chars().any(|c| c.is_numeric());
                    new_requirements[4] = password.chars().any(|c| !c.is_alphanumeric());
                    password_requirements.set(new_requirements);
                },
                "confirm_password" => new_form.confirm_password = input.value(),
                _ => (),
            }
            form.set(new_form);
        })
    };

    let form_is_valid = password_requirements.iter().all(|&x| x) && 
        !form.new_password.is_empty() && 
        !form.confirm_password.is_empty() &&
        form.new_password == form.confirm_password;

    html! {
        <div class="auth">
            <div class="auth__card">
                <div class="auth__header">
                    <h1 class="auth__title">{"Set New Password"}</h1>
                </div>
                <form {onsubmit} class="auth__form">
                <div class="auth__form-group">
                    <label class="auth__label" for="new_password">{"New Password"}</label>
                    <input
                        class="auth__input"
                        type="password"
                        id="new_password"
                        name="new_password"
                        value={form.new_password.clone()}
                        oninput={oninput.clone()}
                        required=true
                        minlength="8"
                    />
                </div>
                <div class="auth__form-group">
                    <label class="auth__label" for="confirm_password">{"Confirm Password"}</label>
                    <input
                        class="auth__input"
                        type="password"
                        id="confirm_password"
                        name="confirm_password"
                        value={form.confirm_password.clone()}
                        oninput={oninput.clone()}
                        required=true
                        minlength="8"
                    />
                </div>
                <div class="auth__requirements">
                    <div class={classes!("auth__requirement", password_requirements[0].then(|| "auth__requirement--met"))}>
                        <i class="fas fa-check"></i>
                        <span>{ "At least 8 characters" }</span>
                    </div>
                    <div class={classes!("auth__requirement", password_requirements[1].then(|| "auth__requirement--met"))}>
                        <i class="fas fa-check"></i>
                        <span>{ "Uppercase letter" }</span>
                    </div>
                    <div class={classes!("auth__requirement", password_requirements[2].then(|| "auth__requirement--met"))}>
                        <i class="fas fa-check"></i>
                        <span>{ "Lowercase letter" }</span>
                    </div>
                    <div class={classes!("auth__requirement", password_requirements[3].then(|| "auth__requirement--met"))}>
                        <i class="fas fa-check"></i>
                        <span>{ "Number" }</span>
                    </div>
                    <div class={classes!("auth__requirement", password_requirements[4].then(|| "auth__requirement--met"))}>
                        <i class="fas fa-check"></i>
                        <span>{ "Special character" }</span>
                    </div>
                </div>
                <button type="submit" class="auth__button" disabled={*is_loading || !form_is_valid}>
                    if *is_loading {
                        {"Updating Password..."}
                    } else {
                        {"Update Password"}
                    }
                </button>
                </form>
                if let Some(err) = &*error {
                    <div class="auth__error">{err}</div>
                }
                if let Some(msg) = &*success {
                    <div class="auth__success">{msg}</div>
                }
            </div>
        </div>
    }
}

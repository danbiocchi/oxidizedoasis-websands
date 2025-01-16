use yew::prelude::*;
use gloo::net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew_router::prelude::*;
use crate::routes::Route;
use gloo::console::log;
use web_sys::HtmlInputElement;

#[derive(Default, Clone, Serialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    success: bool,
    message: String,
    data: Option<RegisterData>,
}

#[derive(Deserialize)]
struct RegisterData {
    user: User,
}

#[derive(Deserialize)]
struct User {
    id: String,
    username: String,
    email: String,
    is_email_verified: bool,
    created_at: String,
}

#[function_component(Register)]
pub fn register() -> Html {
    let form = use_state(RegisterForm::default);
    let error = use_state(|| None::<String>);
    let is_loading = use_state(|| false);
    let navigator = use_navigator().unwrap();

    let password_requirements = use_state(|| vec![false; 5]);

    let onsubmit = {
        let form = form.clone();
        let error = error.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let form = form.clone();
            let error = error.clone();
            let is_loading = is_loading.clone();
            let navigator = navigator.clone();

            // Validate email is not empty
            if form.email.trim().is_empty() {
                error.set(Some("Email is required".to_string()));
                return;
            }

            is_loading.set(true);
            error.set(None);

            spawn_local(async move {
                let response = Request::post("/users/register")
                    .json(&*form)
                    .expect("Failed to build request")
                    .send()
                    .await;

                is_loading.set(false);

                match response {
                    Ok(resp) => {
                        let status = resp.status();
                        log!("Response status:", status);

                        match resp.json::<RegisterResponse>().await {
                            Ok(data) => {
                                log!("Registration response:", &data.message);
                                if data.success {
                                    navigator.push(&Route::RegistrationComplete);
                                } else {
                                    error.set(Some(data.message));
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
        let error = error.clone();

        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            let mut new_form = (*form).clone();
            match input.name().as_str() {
                "username" => new_form.username = input.value(),
                "email" => {
                    new_form.email = input.value();
                    if !new_form.email.trim().is_empty() {
                        error.set(None);
                    }
                },
                "password" => {
                    new_form.password = input.value();
                    let password = &new_form.password;
                    let mut new_requirements = vec![false; 5];
                    new_requirements[0] = password.len() >= 8;
                    new_requirements[1] = password.chars().any(|c| c.is_uppercase());
                    new_requirements[2] = password.chars().any(|c| c.is_lowercase());
                    new_requirements[3] = password.chars().any(|c| c.is_numeric());
                    new_requirements[4] = password.chars().any(|c| !c.is_alphanumeric());
                    password_requirements.set(new_requirements);
                },
                _ => (),
            }
            form.set(new_form);
        })
    };

    let form_is_valid = !form.email.trim().is_empty()
        && !form.username.trim().is_empty()
        && password_requirements.iter().all(|&x| x);

    html! {
        <div class="auth-container">
            <div class="auth-card">
                <h1>{ "Sign Up to OxidizedOasis" }</h1>
                <form class="auth-form" {onsubmit}>
                <div class="form-group">
                    <label for="username">{ "Username" }</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        value={form.username.clone()}
                        oninput={oninput.clone()}
                        required=true
                    />
                </div>
                <div class="form-group">
                    <label for="email">{ "Email" }</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={form.email.clone()}
                        oninput={oninput.clone()}
                        required=true
                    />
                </div>
                <div class="form-group">
                    <label for="password">{ "Password" }</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        value={form.password.clone()}
                        oninput={oninput.clone()}
                        required=true
                    />
                </div>
                <div class="password-requirements">
                    <div class={classes!("requirement", password_requirements[0].then(|| "met"))}>
                        { "At least 8 characters" }
                    </div>
                    <div class={classes!("requirement", password_requirements[1].then(|| "met"))}>
                        { "Uppercase letter" }
                    </div>
                    <div class={classes!("requirement", password_requirements[2].then(|| "met"))}>
                        { "Lowercase letter" }
                    </div>
                    <div class={classes!("requirement", password_requirements[3].then(|| "met"))}>
                        { "Number" }
                    </div>
                    <div class={classes!("requirement", password_requirements[4].then(|| "met"))}>
                        { "Special character" }
                    </div>
                </div>
                    <button type="submit" class="auth-button" disabled={*is_loading || !form_is_valid}>
                        { if *is_loading { "Signing Up..." } else { "Sign Up" } }
                    </button>
                </form>
                if let Some(err) = &*error {
                    <div class="error-banner">{ err }</div>
                }
                <div class="auth-links">
                    <Link<Route> to={Route::Login}>{ "Already have an account? Log in" }</Link<Route>>
                </div>
            </div>
        </div>
    }
}

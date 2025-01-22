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
        <div class={classes!("auth", "auth--register")}>
            <div class="auth__card">
                <div class="auth__header">
                    <h1 class="auth__title" id="register-title">{ "Sign Up to Cipher Horizon" }</h1>
                </div>
                <form {onsubmit} class="auth__form">
                <div class="auth__form-group">
                    <label class="auth__label" for="username">{ "Username" }</label>
                    <input
                        class="auth__input"
                        type="text"
                        id="username"
                        name="username"
                        value={form.username.clone()}
                        oninput={oninput.clone()}
                        required=true
                    />
                </div>
                <div class="auth__form-group">
                    <label class="auth__label" for="email">{ "Email" }</label>
                    <input
                        class="auth__input"
                        type="email"
                        id="email"
                        name="email"
                        value={form.email.clone()}
                        oninput={oninput.clone()}
                        required=true
                    />
                </div>
                <div class="auth__form-group">
                    <label class="auth__label" for="password">{ "Password" }</label>
                    <input
                        class="auth__input"
                        type="password"
                        id="password"
                        name="password"
                        value={form.password.clone()}
                        oninput={oninput.clone()}
                        required=true
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
                <button 
                    type="submit" 
                    class="auth__button" 
                    disabled={*is_loading || !form_is_valid}
                >
                    { if *is_loading { "Signing Up..." } else { "Sign Up" } }
                </button>
                </form>
                if let Some(err) = &*error {
                    <div class="auth__error">{ err }</div>
                }
                <div class="auth__links">
                    <Link<Route> to={Route::Login} classes="auth__link">
                        { "Already have an account? Log in" }
                    </Link<Route>>
                </div>
            </div>
        </div>
    }
}

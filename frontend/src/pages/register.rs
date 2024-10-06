// frontend/src/pages/register.rs
use yew::prelude::*;
use web_sys::HtmlInputElement;
use gloo::net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew_router::prelude::*;
use crate::routes::Route;
use gloo::console::log;

#[derive(Default, Clone, Serialize)]
struct RegisterForm {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    message: String,
    user: User,
}

#[derive(Deserialize)]
struct User {
    id: String,
    username: String,
    email: String,
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
                        if resp.status() == 201 {
                            match resp.json::<RegisterResponse>().await {
                                Ok(register_resp) => {
                                    log!("Registration successful: ", &register_resp.message);
                                    navigator.push(&Route::RegistrationComplete);
                                },
                                Err(e) => {
                                    log!("Failed to parse registration response: ", e.to_string());
                                    error.set(Some("An error occurred. Please try again.".to_string()));
                                }
                            }
                        } else {
                            let err_message = resp.text().await.unwrap_or_else(|_| "An error occurred".to_string());
                            error.set(Some(err_message));
                        }
                    }
                    Err(e) => {
                        log!("Network error: ", e.to_string());
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
                "username" => new_form.username = input.value(),
                "email" => new_form.email = input.value(),
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

    html! {
    <div class="auth-form-container">
        <h2>{ "Sign Up to OxidizedOasis" }</h2>
        <form {onsubmit}>
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
            <button type="submit" disabled={*is_loading || !password_requirements.iter().all(|&x| x)}>
                { if *is_loading { "Signing Up..." } else { "Sign Up" } }
            </button>
        </form>
        if let Some(err) = &*error {
            <p class="error-message">{ err }</p>
        }
        <p class="auth-switch">
            { "Already have an account? " }
            <Link<Route> to={Route::Login}>{ "Log in" }</Link<Route>>
        </p>
    </div>
    }
}
use yew::prelude::*;
use web_sys::HtmlInputElement;
use gloo::net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use crate::services::auth;
use crate::services::auth_context::AuthContext;
use yew_router::prelude::*;
use crate::routes::Route;
use gloo::console::log;

#[derive(Default, Clone, Serialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    message: String,
    token: String,
    user: User,
}

#[derive(Deserialize)]
struct ErrorResponse {
    message: String,
    error_type: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: String,
    username: String,
}

#[function_component(Login)]
pub fn login() -> Html {
    let auth_context = use_context::<AuthContext>().expect("No auth context found");
    let form = use_state(LoginForm::default);
    let error = use_state(|| None::<String>);
    let is_loading = use_state(|| false);
    let navigator = use_navigator().unwrap();

    let onsubmit = {
        let form = form.clone();
        let error = error.clone();
        let is_loading = is_loading.clone();
        let navigator = navigator.clone();
        let set_auth = auth_context.set_auth.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let form = form.clone();
            let error = error.clone();
            let is_loading = is_loading.clone();
            let navigator = navigator.clone();
            let set_auth = set_auth.clone();

            is_loading.set(true);
            error.set(None);

            spawn_local(async move {
                let response = Request::post("/users/login")
                    .json(&*form)
                    .expect("Failed to build request")
                    .send()
                    .await;

                is_loading.set(false);

                match response {
                    Ok(resp) => {
                        if resp.status() == 200 {
                            match resp.json::<LoginResponse>().await {
                                Ok(login_resp) => {
                                    log!("Login successful: ", &login_resp.message);
                                    auth::set_token(&login_resp.token);
                                    set_auth.emit(true);
                                    navigator.push(&Route::Dashboard);
                                },
                                Err(e) => {
                                    log!("Failed to parse login response: ", e.to_string());
                                    error.set(Some("An error occurred. Please try again.".to_string()));
                                }
                            }
                        } else {
                            match resp.json::<ErrorResponse>().await {
                                Ok(err_resp) => {
                                    log!("Login error: ", &err_resp.message);
                                    if err_resp.error_type == Some("email_not_verified".to_string()) {
                                        error.set(Some("Please verify your email before logging in.".to_string()));
                                    } else {
                                        error.set(Some(err_resp.message));
                                    }
                                },
                                Err(e) => {
                                    log!("Failed to parse error response: ", e.to_string());
                                    error.set(Some("An error occurred. Please try again.".to_string()));
                                }
                            }
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
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            let mut new_form = (*form).clone();
            match input.name().as_str() {
                "username" => new_form.username = input.value(),
                "password" => new_form.password = input.value(),
                _ => (),
            }
            form.set(new_form);
        })
    };

    html! {
        <main class="login-content">
            <div class="login-container">
                <h1>{"Login to OxidizedOasis"}</h1>
                <form {onsubmit} class="login-form">
                    <div class="form-group">
                        <label for="username">{"Username"}</label>
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
                        <label for="password">{"Password"}</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            value={form.password.clone()}
                            oninput={oninput.clone()}
                            required=true
                        />
                    </div>
                    <button type="submit" class="login-button" disabled={*is_loading}>
                        if *is_loading {
                            {"Logging in..."}
                        } else {
                            {"Login"}
                        }
                    </button>
                </form>
                if let Some(err) = &*error {
                    <p class="error-message">{err}</p>
                }
            </div>
        </main>
    }
}
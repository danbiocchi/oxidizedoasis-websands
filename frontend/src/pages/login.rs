use web_sys::HtmlInputElement;
use yew::prelude::*;
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
    success: bool,
    message: String,
    data: Option<LoginData>,
}

#[derive(Deserialize)]
struct LoginData {
    token: String,
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
                        log!("Response status:", resp.status());

                        match resp.json::<LoginResponse>().await {
                            Ok(login_resp) => {
                                if login_resp.success {
                                    if let Some(data) = login_resp.data {
                                        log!("Login successful");
                                        auth::set_token(&data.token);
                                        set_auth.emit(true);
                                        navigator.push(&Route::Dashboard);
                                    } else {
                                        error.set(Some("Invalid server response".to_string()));
                                    }
                                } else {
                                    error.set(Some(login_resp.message));
                                }
                            },
                            Err(e) => {
                                log!("Failed to parse login response:", e.to_string());
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
            <div class="auth-form-container">
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
                <p class="auth-switch">
                    { "Don't have an account? " }
                    <Link<Route> to={Route::Register}>{ "Register" }</Link<Route>>
                </p>
            </div>
        </main>
    }
}
use web_sys::HtmlInputElement;
use yew::prelude::*;
use gloo::net::http::Request;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use yew_router::prelude::*;
use crate::routes::Route;

#[derive(Default, Clone, Serialize)]
struct PasswordResetForm {
    email: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

#[function_component(PasswordResetRequest)]
pub fn password_reset_request() -> Html {
    let form = use_state(PasswordResetForm::default);
    let error = use_state(|| None::<String>);
    let success = use_state(|| None::<String>);
    let is_loading = use_state(|| false);

    let onsubmit = {
        let form = form.clone();
        let error = error.clone();
        let success = success.clone();
        let is_loading = is_loading.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let form = form.clone();
            let error = error.clone();
            let success = success.clone();
            let is_loading = is_loading.clone();

            is_loading.set(true);
            error.set(None);
            success.set(None);

            spawn_local(async move {
                let response = Request::post("/users/password-reset/request")
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
                                    success.set(Some(api_resp.message));
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
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            let mut new_form = (*form).clone();
            if input.name() == "email" {
                new_form.email = input.value();
            }
            form.set(new_form);
        })
    };

    html! {
        <div class="auth">
            <div class="auth__card">
                <div class="auth__header">
                    <h1 class="auth__title">{"Reset Password"}</h1>
                    <p class="auth__subtitle">
                        {"Enter your email address and we'll send you instructions to reset your password."}
                    </p>
                </div>
                <form {onsubmit} class="auth__form">
                    <div class="auth__form-group">
                        <label class="auth__label" for="email">{"Email"}</label>
                        <input
                            class="auth__input"
                            type="email"
                            id="email"
                            name="email"
                            value={form.email.clone()}
                            oninput={oninput}
                            required=true
                        />
                    </div>
                    <button type="submit" class="auth__button" disabled={*is_loading}>
                        if *is_loading {
                            {"Sending..."}
                        } else {
                            {"Send Reset Instructions"}
                        }
                    </button>
                </form>
                if let Some(err) = &*error {
                    <div class="auth__error">{err}</div>
                }
                if let Some(msg) = &*success {
                    <div class="auth__success">{msg}</div>
                }
                <div class="auth__links">
                    <Link<Route> to={Route::Login} classes="auth__link">{ "Back to Login" }</Link<Route>>
                </div>
            </div>
        </div>
    }
}

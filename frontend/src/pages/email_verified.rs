use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;
use crate::confetti::trigger_confetti;
use web_sys::window;

#[function_component(EmailVerified)]
pub fn email_verified() -> Html {
    use_effect(|| {
        let cleanup_handle = trigger_confetti();

        move || {
            // This closure will be called when the component is unmounted
            if let Some(window) = window() {
                window.clear_interval_with_handle(cleanup_handle);
            }
        }
    });

    html! {
        <div class="container email-verified">
            <h1>{"Your Account Has Been Verified!"}</h1>
            <p>{"Thank you for verifying your email address. You can now log in to your account and start using OxidizedOasis."}</p>
            <Link<Route> to={Route::Login} classes="button">{"Log In"}</Link<Route>>
        </div>
    }
}
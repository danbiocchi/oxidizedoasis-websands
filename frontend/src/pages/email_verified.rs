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
        <div class="auth auth--verified">
            <h1 class="auth__title">{"Your Account Has Been Verified!"}</h1>
            <div class="auth__content">
                <p class="auth__message">{"Thank you for verifying your email address. You can now log in to your account and start using OxidizedOasis."}</p>
            </div>
            <div class="auth__links">
                <Link<Route> to={Route::Login} classes="auth__button">{"Log In"}</Link<Route>>
            </div>
        </div>
    }
}

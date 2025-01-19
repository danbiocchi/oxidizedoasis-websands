use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;

#[function_component(RegistrationComplete)]
pub fn registration_complete() -> Html {
    html! {
        <div class="auth auth--complete">
            <h1 class="auth__title">{"Registration Complete!"}</h1>
            <div class="auth__content">
                <p class="auth__message">{"Thank you for registering with OxidizedOasis. We've sent a verification email to your registered email address."}</p>
                <p class="auth__message">{"Please check your inbox and click on the verification link to activate your account. The link will expire in 24 hours."}</p>
                <p class="auth__message">{"If you don't see the email in your inbox, please check your spam folder."}</p>
            </div>
            <div class="auth__links">
                <Link<Route> to={Route::Login} classes="auth__button">{"Go to Login"}</Link<Route>>
            </div>
        </div>
    }
}

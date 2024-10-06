use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;

#[function_component(RegistrationComplete)]
pub fn registration_complete() -> Html {
    html! {
        <div class="container registration-complete">
            <h1>{"Registration Complete!"}</h1>
            <p>{"Thank you for registering with OxidizedOasis. We've sent a verification email to your registered email address."}</p>
            <p>{"Please check your inbox and click on the verification link to activate your account. The link will expire in 24 hours."}</p>
            <p>{"If you don't see the email in your inbox, please check your spam folder."}</p>
            <Link<Route> to={Route::Login} classes="button">{"Go to Login"}</Link<Route>>
        </div>
    }
}
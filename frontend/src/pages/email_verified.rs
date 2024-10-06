use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;

#[function_component(EmailVerified)]
pub fn email_verified() -> Html {
    html! {
        <div class="container email-verified">
            <h1>{"Your Account Has Been Verified!"}</h1>
            <p>{"Thank you for verifying your email address. You can now log in to your account and start using OxidizedOasis."}</p>
            <Link<Route> to={Route::Login} classes="button">{"Log In"}</Link<Route>>
        </div>
    }
}
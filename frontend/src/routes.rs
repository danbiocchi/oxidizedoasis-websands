use yew::prelude::*;
use yew_router::prelude::*;
use crate::pages::{
    Home, About, Login, Dashboard, Register, EmailVerified, RegistrationComplete,
    PasswordResetRequest, PasswordResetVerify, PasswordResetNew
};

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/about")]
    About,
    #[at("/login")]
    Login,
    #[at("/dashboard")]
    Dashboard,
    #[at("/register")]
    Register,
    #[at("/email_verified")]
    EmailVerified,
    #[at("/registration_complete")]
    RegistrationComplete,
    #[at("/password-reset")]
    PasswordResetRequest,
    #[at("/password-reset/verify")]
    PasswordResetVerify,
    #[at("/password-reset/new")]
    PasswordResetNew,  // Token is handled through context instead of route params
    #[not_found]
    #[at("/404")]
    NotFound,
}

pub fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::About => html! { <About /> },
        Route::Login => html! { <Login /> },
        Route::Dashboard => html! { <Dashboard /> },
        Route::Register => html! { <Register /> },
        Route::EmailVerified => html! { <EmailVerified /> },
        Route::RegistrationComplete => html! { <RegistrationComplete /> },
        Route::PasswordResetRequest => html! { <PasswordResetRequest /> },
        Route::PasswordResetVerify => html! { <PasswordResetVerify /> },
        Route::PasswordResetNew => html! { <PasswordResetNew /> },
        Route::NotFound => html! { <h1>{"404 Not Found"}</h1> },
    }
}

use yew::prelude::*;
use yew_router::prelude::*;
use crate::pages::{Home, About, Login, Dashboard, Register};


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
}

pub fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::About => html! { <About /> },
        Route::Login => html! { <Login /> },
        Route::Dashboard => html! { <Dashboard /> },
        Route::Register => html! { <Register /> },
    }
}
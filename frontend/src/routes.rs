use yew::prelude::*;
use yew_router::prelude::*;
use crate::pages::{Home, About, Login, Dashboard};
use crate::services::auth;

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
}

pub fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::About => html! { <About /> },
        Route::Login => html! { <Login /> },
        Route::Dashboard => {
            if auth::is_authenticated() {
                html! { <Dashboard /> }
            } else {
                html! { <Redirect<Route> to={Route::Login}/> }
            }
        },
    }
}
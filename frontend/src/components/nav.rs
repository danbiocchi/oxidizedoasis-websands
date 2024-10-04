// frontend/src/components/nav.rs
use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;

#[function_component(Nav)]
pub fn nav() -> Html {
    html! {
        <nav>
            <ul>
                <li><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>></li>
                <li><Link<Route> to={Route::Login}>{ "Login" }</Link<Route>></li>
                <li><Link<Route> to={Route::About}>{ "About" }</Link<Route>></li>
                <li><Link<Route> to={Route::Dashboard}>{ "Dashboard" }</Link<Route>></li>
            </ul>
        </nav>
    }
}
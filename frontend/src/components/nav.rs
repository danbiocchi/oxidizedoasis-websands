use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;

#[function_component(Nav)]
pub fn nav() -> Html {
    html! {
        <nav class="navbar">
            <div class="navbar-container">
                <ul class="nav-links">
                    <li><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>></li>
                    <li><Link<Route> to={Route::About}>{ "About" }</Link<Route>></li>
                    <li><Link<Route> to={Route::Dashboard}>{ "Dashboard" }</Link<Route>></li>
                </ul>
                <div class="nav-login">
                    <Link<Route> to={Route::Login}>{ "Login" }</Link<Route>>
                </div>
            </div>
        </nav>
    }
}
use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;
use crate::services::auth_context::AuthContext;
use crate::services::auth;

#[function_component(Nav)]
pub fn nav() -> Html {
    let auth_context = use_context::<AuthContext>().expect("No auth context found");
    let navigator = use_navigator().unwrap();

    let logout = {
        let navigator = navigator.clone();
        let set_auth = auth_context.set_auth.clone();
        Callback::from(move |_| {
            auth::remove_token();
            set_auth.emit(false);
            navigator.push(&Route::Home);
        })
    };

    html! {
        <nav class="navbar">
            <div class="navbar-container">
                <ul class="nav-links">
                    <li><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>></li>
                    <li><Link<Route> to={Route::About}>{ "About" }</Link<Route>></li>
                    if auth_context.is_authenticated {
                        <li><Link<Route> to={Route::Dashboard}>{ "Dashboard" }</Link<Route>></li>
                    }
                </ul>
                <div class="navbar-auth">
                    if auth_context.is_authenticated {
                        <button class="logout-button" onclick={logout}>{ "Logout" }</button>
                    } else {
                        <button class="login-button" onclick={Callback::from(move |_| navigator.push(&Route::Login))}>{ "Login" }</button>
                    }
                </div>
            </div>
        </nav>
    }
}
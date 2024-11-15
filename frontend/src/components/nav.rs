use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;
use crate::services::auth_context::AuthContext;
use crate::services::auth;

#[function_component(Nav)]
pub fn nav() -> Html {
    let auth_context = use_context::<AuthContext>().expect("No auth context found");
    let navigator = use_navigator().unwrap();

    // General navigation helper
    let navigate = |route: Route| {
        let navigator = navigator.clone();
        Callback::from(move |_| {
            navigator.push(&route);
        })
    };

    // Specific logout handler
    let logout = {
        let navigator = navigator.clone();
        let set_auth = auth_context.set_auth.clone();
        Callback::from(move |_| {
            auth::logout();
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
                <div class="auth-buttons">
                    if auth_context.is_authenticated {
                        <button onclick={logout} class="auth-button logout-button">
                            { "Logout" }
                        </button>
                    } else {
                        <>
                            <button onclick={navigate(Route::Login)}
                                    class="auth-button login-button">
                                { "Login" }
                            </button>
                            <button onclick={navigate(Route::Register)}
                                    class="auth-button register-button">
                                { "Register" }
                            </button>
                        </>
                    }
                </div>
            </div>
        </nav>
    }
}
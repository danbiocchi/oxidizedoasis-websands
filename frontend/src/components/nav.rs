use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route;
use crate::services::auth_context::AuthContext;
use crate::services::auth;

#[function_component(Nav)]
pub fn nav() -> Html {
    let auth_context = use_context::<AuthContext>().expect("No auth context found");
    let navigator = use_navigator().unwrap();
    let is_menu_open = use_state(|| false);

    // Mobile menu toggle handler
    let toggle_menu = {
        let is_menu_open = is_menu_open.clone();
        Callback::from(move |_| {
            is_menu_open.set(!*is_menu_open);
        })
    };

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
            navigator.push(&Route::Login);
        })
    };

    html! {
        <nav class="c-navbar">
            <div class="c-navbar__content">
                <div class="c-navbar__brand-group">
                    <Link<Route> classes="c-navbar__brand" to={Route::Home}>
                        { "WebSands" }
                    </Link<Route>>
                    <Link<Route> classes="c-navbar__link" to={Route::About}>{ "About" }</Link<Route>>
                    if auth_context.is_authenticated {
                        <Link<Route> classes="c-navbar__link" to={Route::Dashboard}>{ "Dashboard" }</Link<Route>>
                    }
                </div>
                <button onclick={toggle_menu.clone()} class="c-navbar__menu-button">
                    if *is_menu_open {
                        { "✕" }
                    } else {
                        { "☰" }
                    }
                </button>
                <div class={classes!("c-navbar__nav", (*is_menu_open).then_some("is-open"))}>
                </div>
                <div class="c-navbar__actions">
                    if auth_context.is_authenticated {
                        <button onclick={logout} class="c-button c-button--error">
                            { "Logout" }
                        </button>
                    } else {
                        <>
                            <button onclick={navigate(Route::Login)}
                                    class="c-button c-button--outline">
                                { "Login" }
                            </button>
                            <button onclick={navigate(Route::Register)}
                                    class="c-button c-button--primary">
                                { "Register" }
                            </button>
                        </>
                    }
                </div>
            </div>
        </nav>
    }
}

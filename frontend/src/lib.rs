use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew_router::prelude::*;

mod components;
mod pages;
mod routes;
mod services;
mod confetti;

use components::nav::Nav;
use routes::{Route, switch};
use services::auth_context::AuthContext;
use components::footer::Footer;
use crate::services::confetti_context::ConfettiContext;

#[wasm_bindgen(start)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<App>::new().render();
    Ok(())
}

#[function_component(App)]
fn app() -> Html {
    let is_authenticated = use_state(|| false);
    let set_auth = {
        let is_authenticated = is_authenticated.clone();
        Callback::from(move |auth: bool| {
            is_authenticated.set(auth);
        })
    };

    let is_confetti_active = use_state(|| false);
    let set_confetti_active = {
        let is_confetti_active = is_confetti_active.clone();
        Callback::from(move |active: bool| {
            is_confetti_active.set(active);
        })
    };

    let auth_context = AuthContext::new(*is_authenticated, set_auth);
    let confetti_context = ConfettiContext::new(*is_confetti_active, set_confetti_active);

    html! {
        <ContextProvider<AuthContext> context={auth_context}>
        <ContextProvider<ConfettiContext> context={confetti_context}>
            <BrowserRouter>
                <Nav />
                <Switch<Route> render={switch} />
                <Footer />
            </BrowserRouter>
        </ContextProvider<ConfettiContext>>
        </ContextProvider<AuthContext>>
    }
}
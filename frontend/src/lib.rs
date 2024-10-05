use wasm_bindgen::prelude::*;
use yew::prelude::*;
use yew_router::prelude::*;

mod components;
mod pages;
mod routes;
mod services;

use components::nav::Nav;
use routes::{Route, switch};
use services::auth_context::AuthContext;

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

    let auth_context = AuthContext::new(*is_authenticated, set_auth);

    html! {
        <ContextProvider<AuthContext> context={auth_context}>
            <BrowserRouter>
                <Nav />
                <Switch<Route> render={switch} />
            </BrowserRouter>
        </ContextProvider<AuthContext>>
    }
}
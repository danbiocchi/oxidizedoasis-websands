// frontend/src/app.rs
use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::{Route, switch};
use crate::components::Nav;

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <Nav />
            <Switch<Route> render={switch} />
        </BrowserRouter>
    }
}
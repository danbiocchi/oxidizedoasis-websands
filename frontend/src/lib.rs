use yew::prelude::*;
use yew_router::prelude::*;

mod routes;

use routes::Route;

mod components;
use components::home::Home;
use components::login::Login;
use components::about::About;
use components::dashboard::Dashboard;
use components::not_found::NotFound;
use crate::components::nav::Nav;

fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::Login => html! { <Login /> },
        Route::About => html! { <About /> },
        Route::Dashboard => html! { <Dashboard /> },
        Route::NotFound => html! { <NotFound /> },
    }
}

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <Nav />
            <Switch<Route> render={switch} /> // <- must be child of <BrowserRouter>
        </BrowserRouter>
    }
}

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<App>::new().render();
    Ok(())
}
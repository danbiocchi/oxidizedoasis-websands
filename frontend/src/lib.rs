use yew::prelude::*;

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <div>
            <h1>{"Welcome to OxidizedOasis-WebSands"}</h1>
            <p>{"This is our first Yew component!"}</p>
        </div>
    }
}

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<App>::new().render();
    Ok(())
}
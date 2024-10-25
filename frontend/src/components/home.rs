// frontend/src/components/home.rs
use yew::prelude::*;

#[function_component(Home)]
pub fn home() -> Html {
    html! {
        <div>
            <h1>{"Welcome to OxidizedOasis-WebSands"}</h1>
            <p>{"This is the home page."}</p>
        </div>
    }
}
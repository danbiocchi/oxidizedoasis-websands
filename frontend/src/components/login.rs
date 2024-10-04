// frontend/src/components/login.rs
use yew::prelude::*;

#[function_component(Login)]
pub fn login() -> Html {
    html! {
        <div>
            <h1>{"Login"}</h1>
            <p>{"Login form will go here."}</p>
        </div>
    }
}
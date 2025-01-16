// frontend/src/components/home.rs
use yew::prelude::*;

#[function_component(Home)]
pub fn home() -> Html {
    html! {
        <div class="welcome-container">
            <h1>{"Welcome to OxidizedOasis-WebSands"}</h1>
            <p>{"Explore our secure and efficient web application. Built with Rust, it offers high performance and robust security features."}</p>
        </div>
    }
}

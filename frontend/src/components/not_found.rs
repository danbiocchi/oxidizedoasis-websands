// frontend/src/components/not_found.rs
use yew::prelude::*;

#[function_component(NotFound)]
pub fn not_found() -> Html {
    html! {
        <div>
            <h1>{"404 - Page Not Found"}</h1>
            <p>{"The page you're looking for doesn't exist."}</p>
        </div>
    }
}
use yew::prelude::*;

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    html! {
        <div>
            <h1>{"Dashboard"}</h1>
            <p>{"User dashboard will go here."}</p>
        </div>
    }
}
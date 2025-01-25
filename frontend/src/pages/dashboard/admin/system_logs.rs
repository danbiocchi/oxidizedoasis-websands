use yew::prelude::*;

pub struct SystemLogs;

impl Component for SystemLogs {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"System Logs"}</h2>
                    <div class="l-grid l-grid--stats">
                        // TODO: Implement system logs UI
                        <p>{"System logs interface coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }
}

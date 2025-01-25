use yew::prelude::*;

pub struct SecurityIncidents;

impl Component for SecurityIncidents {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Security Incidents"}</h2>
                    <div class="l-grid l-grid--stats">
                        // TODO: Implement security incidents UI
                        <p>{"Security incidents interface coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }
}

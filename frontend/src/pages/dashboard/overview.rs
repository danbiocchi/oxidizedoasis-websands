use yew::prelude::*;

pub struct Overview;

impl Component for Overview {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Dashboard Overview"}</h2>
                    <div class="l-grid l-grid--stats">
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                <circle cx="8.5" cy="7" r="4"></circle>
                                <polyline points="17 11 19 13 23 9"></polyline>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Account Status"}</span>
                                <span class="c-card__value">{"Active"}</span>
                            </div>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Session Time"}</span>
                                <span class="c-card__value">{"00:00:00"}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}

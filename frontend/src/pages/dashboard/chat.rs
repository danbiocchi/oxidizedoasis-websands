use yew::prelude::*;

pub struct Chat;

impl Component for Chat {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Chat"}</h2>
                    <div class="l-grid l-grid--stats">
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Messages"}</span>
                                <span class="c-card__value">{"0"}</span>
                            </div>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="4"></circle>
                                <path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"></path>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Online Status"}</span>
                                <span class="c-card__value">{"Available"}</span>
                            </div>
                        </div>
                    </div>
                    <div class="chat-placeholder" style="margin-top: 20px; text-align: center;">
                        <p>{"Chat functionality coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }
}
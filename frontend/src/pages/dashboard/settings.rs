use yew::prelude::*;

pub struct Settings;

impl Component for Settings {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Settings"}</h2>
                    <div class="l-grid l-grid--stats">
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 17H2a3 3 0 0 0 3-3V9a7 7 0 0 1 14 0v5a3 3 0 0 0 3 3zm-8.27 4a2 2 0 0 1-3.46 0"></path>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Email Notifications"}</span>
                                <span class="c-card__value">
                                    <div class="c-form-check">
                                        <input type="checkbox" class="c-form-check-input" checked=true />
                                    </div>
                                </span>
                            </div>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Two-Factor Authentication"}</span>
                                <span class="c-card__value">
                                    <div class="c-form-check">
                                        <input type="checkbox" class="c-form-check-input" />
                                    </div>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}

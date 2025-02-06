use yew::prelude::*;

pub struct Data;

impl Component for Data {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Data"}</h2>
                    <div class="l-grid l-grid--stats">
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="17 8 12 3 7 8"></polyline>
                                <line x1="12" y1="3" x2="12" y2="15"></line>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Storage Used"}</span>
                                <span class="c-card__value">{"0 MB"}</span>
                            </div>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                <polyline points="13 2 13 9 20 9"></polyline>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Files"}</span>
                                <span class="c-card__value">{"0"}</span>
                            </div>
                        </div>
                    </div>
                    <div class="data-upload" style="margin-top: 20px; text-align: center;">
                        <label class="c-button c-button--primary" style="cursor: pointer;">
                            {"Upload Files"}
                            <input type="file" multiple=true style="display: none;"/>
                        </label>
                        <p style="margin-top: 10px;">{"Drag and drop files here or click to upload"}</p>
                    </div>
                </div>
            </div>
        }
    }
}
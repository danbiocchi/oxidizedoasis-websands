use yew::prelude::*;

pub struct AppearanceSettings;

impl Component for AppearanceSettings {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="settings-tab">
                <h3 class="settings-tab__title">{"Appearance Settings"}</h3>
                
                <div class="settings-tab__content">
                    <div class="c-card">
                        <h4 class="c-card__title">{"Theme"}</h4>
                        
                        <div class="c-form-group">
                            <label class="c-form-label">{"Theme Mode"}</label>
                            <div class="c-form-check">
                                <input type="radio" id="theme-light" name="theme" class="c-form-check-input" disabled=true />
                                <label class="c-form-check-label" for="theme-light">{"Light"}</label>
                            </div>
                            <div class="c-form-check">
                                <input type="radio" id="theme-dark" name="theme" class="c-form-check-input" disabled=true />
                                <label class="c-form-check-label" for="theme-dark">{"Dark"}</label>
                            </div>
                            <div class="c-form-check">
                                <input type="radio" id="theme-system" name="theme" class="c-form-check-input" checked=true disabled=true />
                                <label class="c-form-check-label" for="theme-system">{"System Default"}</label>
                            </div>
                            <small class="c-form-help">{"Coming soon"}</small>
                        </div>
                    </div>
                    
                    <div class="c-card">
                        <h4 class="c-card__title">{"Accessibility"}</h4>
                        
                        <div class="c-form-group">
                            <label class="c-form-label">{"Font Size"}</label>
                            <select class="c-form-select" disabled=true>
                                <option>{"Small"}</option>
                                <option selected=true>{"Medium (Default)"}</option>
                                <option>{"Large"}</option>
                                <option>{"Extra Large"}</option>
                            </select>
                            <small class="c-form-help">{"Coming soon"}</small>
                        </div>
                        
                        <div class="c-form-group">
                            <div class="c-form-check">
                                <input type="checkbox" id="high-contrast" class="c-form-check-input" disabled=true />
                                <label class="c-form-check-label" for="high-contrast">{"High Contrast Mode"}</label>
                            </div>
                            <small class="c-form-help">{"Coming soon"}</small>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
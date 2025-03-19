use yew::prelude::*;

pub struct PrivacySettings;

impl Component for PrivacySettings {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="settings-tab">
                <h3 class="settings-tab__title">{"Privacy Settings"}</h3>
                
                <div class="settings-tab__content">
                    <div class="c-card">
                        <h4 class="c-card__title">{"Data Sharing"}</h4>
                        
                        <div class="c-form-group">
                            <div class="c-form-check">
                                <input type="checkbox" id="usage-data" class="c-form-check-input" checked=true disabled=true />
                                <label class="c-form-check-label" for="usage-data">{"Share Usage Data"}</label>
                            </div>
                            <small class="c-form-help">{"Allow us to collect anonymous usage data to improve the application (Coming soon)"}</small>
                        </div>
                    </div>
                    
                    <div class="c-card">
                        <h4 class="c-card__title">{"Data Export"}</h4>
                        
                        <p>{"You can request a copy of all your personal data stored in our system."}</p>
                        
                        <div class="c-form-actions">
                            <button class="c-button c-button--secondary" disabled=true>
                                {"Request Data Export"}
                            </button>
                        </div>
                        <small class="c-form-help">{"Coming soon"}</small>
                    </div>
                </div>
            </div>
        }
    }
}
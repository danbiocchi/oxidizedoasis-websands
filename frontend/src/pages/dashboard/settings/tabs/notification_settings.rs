use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;

// Placeholder for API functions that will be implemented later
// use crate::api::user::{get_user_preferences, update_user_preferences};

pub struct NotificationSettings {
    email_notifications: bool,
    in_app_notifications: bool,
    is_loading: bool,
    error_message: Option<String>,
    success_message: Option<String>,
}

pub enum Msg {
    PreferencesLoaded(bool, bool),
    ToggleEmailNotifications(bool),
    ToggleInAppNotifications(bool),
    SavePreferences,
    PreferencesSaved,
    SetError(String),
    ClearMessages,
}

impl Component for NotificationSettings {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        // Load user preferences
        // This is a placeholder for the actual API call
        let link = ctx.link().clone();
        
        // Simulate API call with a timeout
        spawn_local(async move {
            gloo::timers::future::TimeoutFuture::new(1000).await;
            link.send_message(Msg::PreferencesLoaded(true, true));
        });

        Self {
            email_notifications: true, // Default value
            in_app_notifications: true, // Default value
            is_loading: true,
            error_message: None,
            success_message: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::PreferencesLoaded(email, in_app) => {
                self.email_notifications = email;
                self.in_app_notifications = in_app;
                self.is_loading = false;
                true
            }
            Msg::ToggleEmailNotifications(enabled) => {
                self.email_notifications = enabled;
                true
            }
            Msg::ToggleInAppNotifications(enabled) => {
                self.in_app_notifications = enabled;
                true
            }
            Msg::SavePreferences => {
                self.is_loading = true;
                let email = self.email_notifications;
                let in_app = self.in_app_notifications;
                let link = ctx.link().clone();
                
                // Simulate API call with a timeout
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(1000).await;
                    link.send_message(Msg::PreferencesSaved);
                });
                
                true
            }
            Msg::PreferencesSaved => {
                self.is_loading = false;
                self.success_message = Some("Notification preferences saved successfully".to_string());
                
                // Clear success message after 5 seconds
                let link = ctx.link().clone();
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(5000).await;
                    link.send_message(Msg::ClearMessages);
                });
                
                true
            }
            Msg::SetError(error) => {
                self.error_message = Some(error);
                self.success_message = None;
                self.is_loading = false;
                true
            }
            Msg::ClearMessages => {
                self.error_message = None;
                self.success_message = None;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        
        html! {
            <div class="settings-tab">
                <h3 class="settings-tab__title">{"Notification Settings"}</h3>
                
                if self.is_loading {
                    <div class="c-loader">{"Loading preferences..."}</div>
                } else {
                    <div class="settings-tab__content">
                        <div class="c-card">
                            <h4 class="c-card__title">{"Notification Preferences"}</h4>
                            
                            if let Some(message) = &self.success_message {
                                <div class="c-alert c-alert--success">{message}</div>
                            }
                            
                            if let Some(error) = &self.error_message {
                                <div class="c-alert c-alert--error">{error}</div>
                            }
                            
                            <div class="c-form-group">
                                <div class="c-form-check">
                                    <input 
                                        type="checkbox" 
                                        id="email-notifications" 
                                        class="c-form-check-input"
                                        checked={self.email_notifications}
                                        onchange={link.callback(|e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Msg::ToggleEmailNotifications(input.checked())
                                        })}
                                    />
                                    <label class="c-form-check-label" for="email-notifications">
                                        {"Email Notifications"}
                                    </label>
                                </div>
                                <small class="c-form-help">
                                    {"Receive important updates and notifications via email"}
                                </small>
                            </div>
                            
                            <div class="c-form-group">
                                <div class="c-form-check">
                                    <input 
                                        type="checkbox" 
                                        id="in-app-notifications" 
                                        class="c-form-check-input"
                                        checked={self.in_app_notifications}
                                        disabled=true
                                        onchange={link.callback(|e: Event| {
                                            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
                                            Msg::ToggleInAppNotifications(input.checked())
                                        })}
                                    />
                                    <label class="c-form-check-label" for="in-app-notifications">
                                        {"In-App Notifications"}
                                    </label>
                                </div>
                                <small class="c-form-help">
                                    {"Receive notifications within the application (Coming soon)"}
                                </small>
                            </div>
                            
                            <div class="c-form-actions">
                                <button 
                                    class="c-button c-button--primary"
                                    onclick={link.callback(|_| Msg::SavePreferences)}
                                    disabled={self.is_loading}
                                >
                                    if self.is_loading {
                                        {"Saving..."}
                                    } else {
                                        {"Save Preferences"}
                                    }
                                </button>
                            </div>
                        </div>
                        
                        // Notification Types Card (Placeholder)
                        <div class="c-card">
                            <h4 class="c-card__title">{"Notification Types"}</h4>
                            <p>{"Configure which types of notifications you want to receive."}</p>
                            <small class="c-form-help">{"Coming soon"}</small>
                        </div>
                    </div>
                }
            </div>
        }
    }
}
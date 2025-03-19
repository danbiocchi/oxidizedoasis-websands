use yew::prelude::*;
use web_sys::HtmlInputElement;
use wasm_bindgen_futures::spawn_local;

// Placeholder for API functions that will be implemented later
// use crate::api::user::{update_user, get_current_user};
// use crate::models::User;

pub struct AccountSettings {
    username: String,
    email: String,
    is_loading: bool,
    error_message: Option<String>,
    success_message: Option<String>,
}

pub enum Msg {
    // UserLoaded(User),
    UpdateUsername(String),
    UpdateEmail(String),
    SaveChanges,
    SaveSuccess(String),
    SaveError(String),
    ClearMessages,
}

impl Component for AccountSettings {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        // Load user data when component is created
        // This is a placeholder for the actual API call
        /*
        let link = ctx.link().clone();
        spawn_local(async move {
            match get_current_user().await {
                Ok(user) => link.send_message(Msg::UserLoaded(user)),
                Err(err) => link.send_message(Msg::SaveError(err.to_string())),
            }
        });
        */

        Self {
            username: "User".to_string(), // Placeholder
            email: "user@example.com".to_string(), // Placeholder
            is_loading: false,
            error_message: None,
            success_message: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            /*
            Msg::UserLoaded(user) => {
                self.username = user.username.clone();
                self.email = user.email.clone().unwrap_or_default();
                self.is_loading = false;
                true
            }
            */
            Msg::UpdateUsername(username) => {
                self.username = username;
                true
            }
            Msg::UpdateEmail(email) => {
                self.email = email;
                true
            }
            Msg::SaveChanges => {
                self.is_loading = true;
                
                // Placeholder for actual API call
                let username = self.username.clone();
                let email = self.email.clone();
                let link = ctx.link().clone();
                
                // Simulate API call with a timeout
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(1000).await;
                    link.send_message(Msg::SaveSuccess("Profile updated successfully".to_string()));
                });
                
                true
            }
            Msg::SaveSuccess(message) => {
                self.success_message = Some(message);
                self.error_message = None;
                self.is_loading = false;
                
                // Clear success message after 5 seconds
                let link = ctx.link().clone();
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(5000).await;
                    link.send_message(Msg::ClearMessages);
                });
                
                true
            }
            Msg::SaveError(error) => {
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
                <h3 class="settings-tab__title">{"Account Settings"}</h3>
                
                if self.is_loading {
                    <div class="c-loader">{"Loading..."}</div>
                } else {
                    <div class="settings-tab__content">
                        // Profile Information Card
                        <div class="c-card">
                            <h4 class="c-card__title">{"Profile Information"}</h4>
                            
                            if let Some(message) = &self.success_message {
                                <div class="c-alert c-alert--success">{message}</div>
                            }
                            
                            if let Some(error) = &self.error_message {
                                <div class="c-alert c-alert--error">{error}</div>
                            }
                            
                            <div class="c-form-group">
                                <label class="c-form-label" for="username">{"Username"}</label>
                                <input 
                                    type="text"
                                    id="username"
                                    class="c-form-input"
                                    value={self.username.clone()}
                                    onchange={link.callback(|e: Event| {
                                        let input: HtmlInputElement = e.target_unchecked_into();
                                        Msg::UpdateUsername(input.value())
                                    })}
                                />
                            </div>
                            
                            <div class="c-form-group">
                                <label class="c-form-label" for="email">{"Email Address"}</label>
                                <input 
                                    type="email"
                                    id="email"
                                    class="c-form-input"
                                    value={self.email.clone()}
                                    onchange={link.callback(|e: Event| {
                                        let input: HtmlInputElement = e.target_unchecked_into();
                                        Msg::UpdateEmail(input.value())
                                    })}
                                />
                                <small class="c-form-help">
                                    {"Changing your email will require verification of the new address"}
                                </small>
                            </div>
                            
                            <div class="c-form-actions">
                                <button 
                                    class="c-button c-button--primary"
                                    onclick={link.callback(|_| Msg::SaveChanges)}
                                    disabled={self.is_loading}
                                >
                                    if self.is_loading {
                                        {"Saving..."}
                                    } else {
                                        {"Save Changes"}
                                    }
                                </button>
                            </div>
                        </div>
                        
                        // Account Management Card
                        <div class="c-card c-card--danger">
                            <h4 class="c-card__title">{"Account Management"}</h4>
                            
                            <p>{"Deleting your account will permanently remove all your data. This action cannot be undone."}</p>
                            
                            <div class="c-form-actions">
                                <button class="c-button c-button--danger">
                                    {"Delete Account"}
                                </button>
                            </div>
                        </div>
                    </div>
                }
            </div>
        }
    }
}
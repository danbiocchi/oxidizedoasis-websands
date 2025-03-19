use yew::prelude::*;
use web_sys::HtmlInputElement;
use wasm_bindgen_futures::spawn_local;

// Placeholder for API functions that will be implemented later
// use crate::api::user::{change_password, get_active_sessions, revoke_session};

#[derive(Clone, PartialEq)]
pub struct Session {
    id: String,
    device_name: String,
    last_active: String,
    is_current: bool,
}

pub struct SecuritySettings {
    current_password: String,
    new_password: String,
    confirm_password: String,
    sessions: Vec<Session>,
    is_loading: bool,
    is_sessions_loading: bool,
    error_message: Option<String>,
    success_message: Option<String>,
}

pub enum Msg {
    UpdateCurrentPassword(String),
    UpdateNewPassword(String),
    UpdateConfirmPassword(String),
    ChangePassword,
    PasswordChanged,
    SessionsLoaded(Vec<Session>),
    RevokeSession(String),
    SessionRevoked(String),
    RevokeAllSessions,
    AllSessionsRevoked,
    SetError(String),
    SetSuccess(String),
    ClearMessages,
}

impl Component for SecuritySettings {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        // Load active sessions
        // This is a placeholder for the actual API call
        let link = ctx.link().clone();
        
        // Simulate API call with a timeout
        spawn_local(async move {
            gloo::timers::future::TimeoutFuture::new(1000).await;
            
            // Mock session data
            let sessions = vec![
                Session {
                    id: "1".to_string(),
                    device_name: "Current Browser".to_string(),
                    last_active: "Just now".to_string(),
                    is_current: true,
                },
                Session {
                    id: "2".to_string(),
                    device_name: "Mobile App".to_string(),
                    last_active: "2 hours ago".to_string(),
                    is_current: false,
                },
                Session {
                    id: "3".to_string(),
                    device_name: "Desktop Browser".to_string(),
                    last_active: "Yesterday".to_string(),
                    is_current: false,
                },
            ];
            
            link.send_message(Msg::SessionsLoaded(sessions));
        });

        Self {
            current_password: String::new(),
            new_password: String::new(),
            confirm_password: String::new(),
            sessions: Vec::new(),
            is_loading: false,
            is_sessions_loading: true,
            error_message: None,
            success_message: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::UpdateCurrentPassword(password) => {
                self.current_password = password;
                true
            }
            Msg::UpdateNewPassword(password) => {
                self.new_password = password;
                true
            }
            Msg::UpdateConfirmPassword(password) => {
                self.confirm_password = password;
                true
            }
            Msg::ChangePassword => {
                // Validate passwords
                if self.new_password != self.confirm_password {
                    self.error_message = Some("New passwords do not match".to_string());
                    return true;
                }
                
                if self.new_password.len() < 8 {
                    self.error_message = Some("Password must be at least 8 characters".to_string());
                    return true;
                }
                
                self.is_loading = true;
                let link = ctx.link().clone();
                
                // Simulate API call with a timeout
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(1000).await;
                    link.send_message(Msg::PasswordChanged);
                });
                
                true
            }
            Msg::PasswordChanged => {
                self.current_password = String::new();
                self.new_password = String::new();
                self.confirm_password = String::new();
                self.is_loading = false;
                self.success_message = Some("Password changed successfully".to_string());
                
                // Clear success message after 5 seconds
                let link = ctx.link().clone();
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(5000).await;
                    link.send_message(Msg::ClearMessages);
                });
                
                true
            }
            Msg::SessionsLoaded(sessions) => {
                self.sessions = sessions;
                self.is_sessions_loading = false;
                true
            }
            Msg::RevokeSession(session_id) => {
                let link = ctx.link().clone();
                let session_id_clone = session_id.clone();
                
                // Simulate API call with a timeout
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(1000).await;
                    link.send_message(Msg::SessionRevoked(session_id_clone));
                });
                
                true
            }
            Msg::SessionRevoked(session_id) => {
                self.sessions.retain(|s| s.id != session_id);
                self.success_message = Some("Session revoked successfully".to_string());
                
                // Clear success message after 5 seconds
                let link = ctx.link().clone();
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(5000).await;
                    link.send_message(Msg::ClearMessages);
                });
                
                true
            }
            Msg::RevokeAllSessions => {
                let link = ctx.link().clone();
                
                // Simulate API call with a timeout
                spawn_local(async move {
                    gloo::timers::future::TimeoutFuture::new(1000).await;
                    link.send_message(Msg::AllSessionsRevoked);
                });
                
                true
            }
            Msg::AllSessionsRevoked => {
                self.sessions.retain(|s| s.is_current);
                self.success_message = Some("All other sessions revoked successfully".to_string());
                
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
            Msg::SetSuccess(message) => {
                self.success_message = Some(message);
                self.error_message = None;
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
                <h3 class="settings-tab__title">{"Security Settings"}</h3>
                
                <div class="settings-tab__content">
                    // Password Change Card
                    <div class="c-card">
                        <h4 class="c-card__title">{"Change Password"}</h4>
                        
                        if let Some(message) = &self.success_message {
                            <div class="c-alert c-alert--success">{message}</div>
                        }
                        
                        if let Some(error) = &self.error_message {
                            <div class="c-alert c-alert--error">{error}</div>
                        }
                        
                        <div class="c-form-group">
                            <label class="c-form-label" for="current-password">{"Current Password"}</label>
                            <input 
                                type="password"
                                id="current-password"
                                class="c-form-input"
                                value={self.current_password.clone()}
                                onchange={link.callback(|e: Event| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdateCurrentPassword(input.value())
                                })}
                            />
                        </div>
                        
                        <div class="c-form-group">
                            <label class="c-form-label" for="new-password">{"New Password"}</label>
                            <input 
                                type="password"
                                id="new-password"
                                class="c-form-input"
                                value={self.new_password.clone()}
                                onchange={link.callback(|e: Event| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdateNewPassword(input.value())
                                })}
                            />
                        </div>
                        
                        <div class="c-form-group">
                            <label class="c-form-label" for="confirm-password">{"Confirm New Password"}</label>
                            <input 
                                type="password"
                                id="confirm-password"
                                class="c-form-input"
                                value={self.confirm_password.clone()}
                                onchange={link.callback(|e: Event| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdateConfirmPassword(input.value())
                                })}
                            />
                        </div>
                        
                        <div class="c-form-actions">
                            <button 
                                class="c-button c-button--primary"
                                onclick={link.callback(|_| Msg::ChangePassword)}
                                disabled={self.is_loading}
                            >
                                if self.is_loading {
                                    {"Changing..."}
                                } else {
                                    {"Change Password"}
                                }
                            </button>
                        </div>
                    </div>
                    
                    // Two-Factor Authentication Card (Placeholder)
                    <div class="c-card">
                        <h4 class="c-card__title">{"Two-Factor Authentication"}</h4>
                        
                        <p>{"Add an extra layer of security to your account by enabling two-factor authentication."}</p>
                        
                        <div class="c-form-group">
                            <div class="c-form-check">
                                <input type="checkbox" id="enable-2fa" class="c-form-check-input" disabled=true />
                                <label class="c-form-check-label" for="enable-2fa">{"Enable Two-Factor Authentication"}</label>
                            </div>
                            <small class="c-form-help">{"Coming soon"}</small>
                        </div>
                    </div>
                    
                    // Active Sessions Card
                    <div class="c-card">
                        <h4 class="c-card__title">{"Active Sessions"}</h4>
                        
                        if self.is_sessions_loading {
                            <div class="c-loader">{"Loading sessions..."}</div>
                        } else if self.sessions.is_empty() {
                            <p>{"No active sessions found."}</p>
                        } else {
                            <div class="c-list">
                                {for self.sessions.iter().map(|session| {
                                    let session_id = session.id.clone();
                                    html! {
                                        <div class="c-list-item">
                                            <div class="c-list-item__content">
                                                <div class="c-list-item__title">
                                                    {&session.device_name}
                                                    if session.is_current {
                                                        <span class="c-badge c-badge--primary">{"Current"}</span>
                                                    }
                                                </div>
                                                <div class="c-list-item__subtitle">
                                                    {"Last active: "}{&session.last_active}
                                                </div>
                                            </div>
                                            <div class="c-list-item__actions">
                                                if !session.is_current {
                                                    <button 
                                                        class="c-button c-button--small c-button--danger"
                                                        onclick={link.callback(move |_| Msg::RevokeSession(session_id.clone()))}
                                                    >
                                                        {"Revoke"}
                                                    </button>
                                                }
                                            </div>
                                        </div>
                                    }
                                })}
                            </div>
                            
                            <div class="c-form-actions">
                                <button 
                                    class="c-button c-button--danger"
                                    onclick={link.callback(|_| Msg::RevokeAllSessions)}
                                >
                                    {"Revoke All Other Sessions"}
                                </button>
                            </div>
                        }
                    </div>
                </div>
            </div>
        }
    }
}
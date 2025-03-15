use yew::prelude::*;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use serde::Deserialize;
use crate::services::auth;
use crate::services::request::{RequestInterceptor, RequestBuilderExt};
use crate::routes::Route;
use yew_router::prelude::*;
use gloo::console::log;
use web_sys::{CustomEvent, EventTarget};
use crate::components::icons::{
    DashboardIcon, ProfileIcon, SettingsIcon,
    UsersIcon, LogsIcon, SecurityIcon,
};

mod overview;
mod profile;
mod settings;
mod admin;
mod chat;
mod data;

pub use overview::Overview;
pub use profile::Profile;
pub use settings::Settings;
pub use chat::Chat;
pub use data::Data;
pub use admin::{UserManagement, SystemLogs, SecurityIncidents};

#[derive(Debug, Clone, PartialEq)]
pub enum DashboardView {
    Overview,
    Profile,
    Chat,
    Data,
    Settings,
    // Admin views
    UserManagement,
    SystemLogs,
    SecurityIncidents,
}

#[derive(Debug, Deserialize)]
struct DashboardResponse {
    success: bool,
    message: Option<String>,
    data: Option<UserData>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserData {
    user: User,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub is_email_verified: bool,
    pub created_at: String,
    pub role: String,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub enum DashboardMsg {
    FetchUserInfo,
    UserInfoFetched(Result<User, String>),
    UpdateNotes(String),
    SaveNotes,
    NotesSaved(Result<(), String>),
    Tick,
    ChangeView(DashboardView),
}

pub struct Dashboard {
    user_info: Option<User>,
    notes: String,
    error: Option<String>,
    timer: u32,
    _interval: Option<Interval>,
    navigator: Navigator,
    current_view: DashboardView,
}

impl Component for Dashboard {
    type Message = DashboardMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let navigator = ctx.link().navigator().unwrap();

        // Check for authentication token
        if !auth::is_authenticated() {
            navigator.push(&Route::Login);
            return Self {
                user_info: None,
                notes: String::new(),
                error: None,
                timer: 0,
                _interval: None,
                navigator,
                current_view: DashboardView::Overview,
            };
        }

        ctx.link().send_message(DashboardMsg::FetchUserInfo);

        let interval = {
            let link = ctx.link().clone();
            Some(Interval::new(1000, move || link.send_message(DashboardMsg::Tick)))
        };

        Self {
            user_info: None,
            notes: LocalStorage::get(NOTES_STORAGE_KEY).unwrap_or_else(|_| String::new()),
            error: None,
            timer: 0,
            _interval: interval,
            navigator,
            current_view: DashboardView::Overview,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            DashboardMsg::FetchUserInfo => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = fetch_user_info().await;
                    link.send_message(DashboardMsg::UserInfoFetched(result));
                });
                false
            }
            DashboardMsg::UserInfoFetched(result) => {
                match result {
                    Ok(user_info) => {
                        self.error = None;
                        self.user_info = Some(user_info);
                    }
                    Err(error) => {
                        self.error = Some(error.clone());
                        if error.contains("unauthorized") {
                            self.navigator.push(&Route::Login);
                        }
                    }
                }
                true
            }
            DashboardMsg::UpdateNotes(new_notes) => {
                self.notes = new_notes;
                true
            }
            DashboardMsg::SaveNotes => {
                match LocalStorage::set(NOTES_STORAGE_KEY, &self.notes) {
                    Ok(_) => self.error = None,
                    Err(e) => self.error = Some(format!("Failed to save notes: {}", e)),
                }
                true
            }
            DashboardMsg::NotesSaved(_) => true,
            DashboardMsg::Tick => {
                self.timer += 1;
                true
            }
            DashboardMsg::ChangeView(view) => {
                match view {
                    DashboardView::Overview | DashboardView::Profile | DashboardView::Chat |
                    DashboardView::Data | DashboardView::Settings | DashboardView::UserManagement |
                    DashboardView::SystemLogs | DashboardView::SecurityIncidents => {
                        self.current_view = view;
                        true
                    }
                }
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-container--dashboard critical-dashboard">
                // Sidebar
                <div class="c-sidebar">
                    <div class="c-sidebar__nav">
                        <div
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Overview { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Overview))}
                        >
                            <DashboardIcon />
                            <span class="c-sidebar__label">{"Overview"}</span>
                        </div>
                        
                        <div
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Profile { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Profile))}
                        >
                            <ProfileIcon />
                            <span class="c-sidebar__label">{"Profile"}</span>
                        </div>
                        
                        <div
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Chat { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Chat))}
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
                            </svg>
                            <span class="c-sidebar__label">{"Chat"}</span>
                        </div>

                        <div
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Data { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Data))}
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                <polyline points="13 2 13 9 20 9"></polyline>
                            </svg>
                            <span class="c-sidebar__label">{"Data"}</span>
                        </div>

                        <div
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Settings { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Settings))}
                        >
                            <SettingsIcon />
                            <span class="c-sidebar__label">{"Settings"}</span>
                        </div>

                        // Admin section
                        if let Some(user) = &self.user_info {
                            if user.is_admin() {
                                <>
                                    <div class="c-sidebar__divider">{"Admin"}</div>
                                    
                                    <div
                                        class={classes!("c-sidebar__item", if self.current_view == DashboardView::UserManagement { "is-active" } else { "" })}
                                        onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::UserManagement))}
                                    >
                                        <UsersIcon />
                                        <span class="c-sidebar__label">{"User Management"}</span>
                                    </div>
                                    
                                    <div
                                        class={classes!("c-sidebar__item", if self.current_view == DashboardView::SystemLogs { "is-active" } else { "" })}
                                        onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::SystemLogs))}
                                    >
                                        <LogsIcon />
                                        <span class="c-sidebar__label">{"System Logs"}</span>
                                    </div>
                                    
                                    <div
                                        class={classes!("c-sidebar__item", if self.current_view == DashboardView::SecurityIncidents { "is-active" } else { "" })}
                                        onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::SecurityIncidents))}
                                    >
                                        <SecurityIcon />
                                        <span class="c-sidebar__label">{"Security Incidents"}</span>
                                    </div>
                                </>
                            }
                        }
                    </div>
                </div>

                // Main content area
                <div class="l-container--dashboard__content">
                    if let Some(error) = &self.error {
                        <div class="c-validation__error">
                            {error}
                        </div>
                    }

                    {self.render_current_view()}
                </div>
            </div>
        }
    }
}

impl Dashboard {
    fn render_current_view(&self) -> Html {
        match self.current_view {
            DashboardView::Overview => html! { <Overview /> },
            DashboardView::Profile => html! { <Profile user={self.user_info.clone()} /> },
            DashboardView::Chat => html! { <Chat /> },
            DashboardView::Data => html! { <Data /> },
            DashboardView::Settings => html! { <Settings /> },
            DashboardView::UserManagement => html! { <UserManagement /> },
            DashboardView::SystemLogs => html! { <SystemLogs /> },
            DashboardView::SecurityIncidents => html! { <SecurityIncidents /> },
        }
    }
}

async fn fetch_user_info() -> Result<User, String> {
    // Use the RequestInterceptor to handle token refresh automatically
    let response = RequestInterceptor::get("/api/cookie/users/me")
        .send_with_retry()
        .await?;
    
    let response_text = response.text().await.map_err(|e| e.to_string())?;
    log!("User info response: {}", &response_text);

    // Parse the response as a JSON Value first to handle CSRF token
    let data_value: serde_json::Value = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    // Store CSRF token if present in the response
    auth::store_csrf_token_from_response(&data_value);

    // Now parse as the proper response type
    let data: DashboardResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response as DashboardResponse: {}", e))?;

    if !data.success {
        return Err(data.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }

    // Extract user data from the response
    if let Some(user_data) = data.data {
        Ok(user_data.user)
    } else {
        Err("No user data in response".into())
    }
}

const NOTES_STORAGE_KEY: &str = "dashboard_notes";

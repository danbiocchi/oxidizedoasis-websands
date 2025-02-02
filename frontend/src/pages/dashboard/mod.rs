use yew::prelude::*;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use serde::Deserialize;
use crate::services::auth;
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

pub use overview::Overview;
pub use profile::Profile;
pub use settings::Settings;
pub use admin::{UserManagement, SystemLogs, SecurityIncidents};

#[derive(Debug, Clone, PartialEq)]
pub enum DashboardView {
    Overview,
    Profile,
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
        if auth::get_token().is_none() {
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
                self.current_view = view;
                true
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
            DashboardView::Settings => html! { <Settings /> },
            DashboardView::UserManagement => html! { <UserManagement /> },
            DashboardView::SystemLogs => html! { <SystemLogs /> },
            DashboardView::SecurityIncidents => html! { <SecurityIncidents /> },
        }
    }
}

async fn fetch_user_info() -> Result<User, String> {
    let token = auth::get_token().ok_or("No auth token found")?;

    let response = gloo::net::http::Request::get("/api/users/me")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e.to_string()))?;

    if !response.ok() {
        return Err("Unauthorized access".to_string());
    }

    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e))?;

    let data: DashboardResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if !data.success {
        return Err(data.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }

    match data.data {
        Some(user_data) => Ok(user_data.user),
        None => Err("No user data in response".to_string()),
    }
}

const NOTES_STORAGE_KEY: &str = "dashboard_notes";

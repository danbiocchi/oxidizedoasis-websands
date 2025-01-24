use yew::prelude::*;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use serde::Deserialize;
use crate::services::auth;
use crate::routes::Route;
use yew_router::prelude::*;
use gloo::console::log;
use crate::components::icons::{
    DashboardIcon, ProfileIcon, SettingsIcon,
    UsersIcon, LogsIcon, SecurityIcon,
};

const NOTES_STORAGE_KEY: &str = "dashboard_notes";

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
struct User {
    id: String,
    username: String,
    email: Option<String>,
    is_email_verified: bool,
    created_at: String,
    role: String,
}

impl User {
    fn is_admin(&self) -> bool {
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
            DashboardView::Overview => self.render_overview(),
            DashboardView::Profile => self.render_profile(),
            DashboardView::Settings => self.render_settings(),
            DashboardView::UserManagement => self.render_user_management(),
            DashboardView::SystemLogs => self.render_system_logs(),
            DashboardView::SecurityIncidents => self.render_security_incidents(),
        }
    }

    fn render_user_management(&self) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"User Management"}</h2>
                    <div class="l-grid l-grid--stats">
                        // TODO: Implement user management UI
                        <p>{"User management interface coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }

    fn render_system_logs(&self) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"System Logs"}</h2>
                    <div class="l-grid l-grid--stats">
                        // TODO: Implement system logs UI
                        <p>{"System logs interface coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }

    fn render_security_incidents(&self) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Security Incidents"}</h2>
                    <div class="l-grid l-grid--stats">
                        // TODO: Implement security incidents UI
                        <p>{"Security incidents interface coming soon..."}</p>
                    </div>
                </div>
            </div>
        }
    }

    fn render_overview(&self) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Dashboard Overview"}</h2>
                    <div class="l-grid l-grid--stats">
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                <circle cx="8.5" cy="7" r="4"></circle>
                                <polyline points="17 11 19 13 23 9"></polyline>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Account Status"}</span>
                                <span class="c-card__value">{"Active"}</span>
                            </div>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            <div class="stat-content">
                                <span class="c-card__label">{"Session Time"}</span>
                                <span class="c-card__value">
                                    {format!("{:02}:{:02}:{:02}",
                                        self.timer / 3600,
                                        (self.timer / 60) % 60,
                                        self.timer % 60
                                    )}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        }
    }

    fn render_profile(&self) -> Html {
        let content = if let Some(user) = &self.user_info {
            html! {
                <div class="l-grid l-grid--stats">
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                            <circle cx="12" cy="7" r="4"></circle>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Username"}</span>
                            <span class="c-card__value">{&user.username}</span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                            <polyline points="22,6 12,13 2,6"></polyline>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Email"}</span>
                            <span class="c-card__value">{user.email.as_deref().unwrap_or("Not provided")}</span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                            <polyline points="22 4 12 14.01 9 11.01"></polyline>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Email Status"}</span>
                            <span class={classes!("c-card__value", if user.is_email_verified { "is-verified" } else { "is-unverified" })}>
                                {if user.is_email_verified { "Verified" } else { "Not Verified" }}
                            </span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="16" y1="2" x2="16" y2="6"></line>
                            <line x1="8" y1="2" x2="8" y2="6"></line>
                            <line x1="3" y1="10" x2="21" y2="10"></line>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Account Created"}</span>
                            <span class="c-card__value">{&user.created_at}</span>
                        </div>
                    </div>
                </div>
            }
        } else {
            html! {
                <div class="c-loader c-loader--circular">{"Loading profile information..."}</div>
            }
        };

        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Profile Information"}</h2>
                    {content}
                </div>
            </div>
        }
    }

    fn render_settings(&self) -> Html {
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

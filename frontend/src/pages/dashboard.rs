use yew::prelude::*;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use serde::Deserialize;
use crate::services::auth;
use crate::routes::Route;
use yew_router::prelude::*;
use gloo::console::log;
use crate::components::icons::{DashboardIcon, ProfileIcon, SettingsIcon};

const NOTES_STORAGE_KEY: &str = "dashboard_notes";

#[derive(Debug, Clone, PartialEq)]
pub enum DashboardView {
    Overview,
    Profile,
    Settings,
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
}

pub enum DashboardMsg {
    FetchUserInfo,
    UserInfoFetched(Result<User, String>),
    UpdateNotes(String),
    SaveNotes,
    NotesSaved(Result<(), String>),
    Tick,
    ToggleSidebar,
    ChangeView(DashboardView),
}

pub struct Dashboard {
    user_info: Option<User>,
    notes: String,
    error: Option<String>,
    timer: u32,
    _interval: Option<Interval>,
    navigator: Navigator,
    sidebar_expanded: bool,
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
                sidebar_expanded: true,
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
            sidebar_expanded: true,
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
            DashboardMsg::ToggleSidebar => {
                self.sidebar_expanded = !self.sidebar_expanded;
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
                <div class={classes!("c-sidebar", if !self.sidebar_expanded { "is-collapsed" } else { "" })}>
                    <div class="c-sidebar__toggle" onclick={ctx.link().callback(|_| DashboardMsg::ToggleSidebar)}>
                        if self.sidebar_expanded {
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polyline points="15 18 9 12 15 6"></polyline>
                            </svg>
                        } else {
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polyline points="9 18 15 12 9 6"></polyline>
                            </svg>
                        }
                    </div>
                    
                    <div class="c-sidebar__nav">
                        <div 
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Overview { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Overview))}
                        >
                            <DashboardIcon />
                            <span class={classes!("c-sidebar__label", if !self.sidebar_expanded { "u-hidden" } else { "" })}>{"Overview"}</span>
                        </div>
                        
                        <div 
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Profile { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Profile))}
                        >
                            <ProfileIcon />
                            <span class={classes!("c-sidebar__label", if !self.sidebar_expanded { "u-hidden" } else { "" })}>{"Profile"}</span>
                        </div>
                        
                        <div 
                            class={classes!("c-sidebar__item", if self.current_view == DashboardView::Settings { "is-active" } else { "" })}
                            onclick={ctx.link().callback(|_| DashboardMsg::ChangeView(DashboardView::Settings))}
                        >
                            <SettingsIcon />
                            <span class={classes!("c-sidebar__label", if !self.sidebar_expanded { "u-hidden" } else { "" })}>{"Settings"}</span>
                        </div>
                        
                    </div>
                </div>

                // Main content area
                <div class={classes!("l-container--dashboard__content", if !self.sidebar_expanded { "is-expanded" } else { "" })}>
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
                            <span class="c-card__label">{"Account Status"}</span>
                            <span class="c-card__value">{"Active"}</span>
                        </div>
                        <div class="c-card c-card--stat">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
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
        }
    }

    fn render_profile(&self) -> Html {
        html! {
            <div class="l-container l-container--md">
                <h2 class="u-text-2xl u-mb-lg">{"Profile Information"}</h2>
                if let Some(user) = &self.user_info {
                    <>
                        <div class="c-card">
                            <div class="c-card__content">
                                <div class="c-card__row">
                                    <span class="c-card__label">{"Username:"}</span>
                                    <span class="c-card__value">{&user.username}</span>
                                </div>
                                <div class="c-card__row">
                                    <span class="c-card__label">{"Email:"}</span>
                                    <span class="c-card__value">{user.email.as_deref().unwrap_or("Not provided")}</span>
                                </div>
                                <div class="c-card__row">
                                    <span class="c-card__label">{"Email Status:"}</span>
                                    <span class={classes!("c-card__value", if user.is_email_verified { "is-verified" } else { "is-unverified" })}>
                                        {if user.is_email_verified { "Verified" } else { "Not Verified" }}
                                    </span>
                                </div>
                                <div class="c-card__row">
                                    <span class="c-card__label">{"Account Created:"}</span>
                                    <span class="c-card__value">{&user.created_at}</span>
                                </div>
                            </div>
                        </div>
                    </>
                } else {
                    <div class="c-loader c-loader--circular">{"Loading profile information..."}</div>
                }
            </div>
        }
    }

    fn render_settings(&self) -> Html {
        html! {
            <div class="l-container l-container--md">
                <h2 class="u-text-2xl u-mb-lg">{"Settings"}</h2>
                <div class="l-grid l-grid--settings">
                    <>
                        <div class="c-card">
                            <h3 class="c-card__title">{"Account Settings"}</h3>
                            <div class="c-card__content">
                                <div class="c-form-check">
                                    <input type="checkbox" class="c-form-check-input" checked=true />
                                    <span class="c-form-check-label">{"Email Notifications"}</span>
                                </div>
                                <div class="c-form-check">
                                    <input type="checkbox" class="c-form-check-input" />
                                    <span class="c-form-check-label">{"Two-Factor Authentication"}</span>
                                </div>
                            </div>
                        </div>
                    </>
                </div>
            </div>
        }
    }
}

async fn fetch_user_info() -> Result<User, String> {
    let token = auth::get_token().ok_or("No auth token found")?;

    log!("Fetching user info with token");

    let response = gloo::net::http::Request::get("/api/users/me")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e.to_string()))?;

    if !response.ok() {
        return Err("Unauthorized access".to_string());
    }

    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e.to_string()))?;

    log!("Response body: {}", &response_text);

    let data: DashboardResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {} - Response was: {}", e, response_text))?;

    if !data.success {
        return Err(data.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }

    match data.data {
        Some(user_data) => Ok(user_data.user),
        None => Err("No user data in response".to_string()),
    }
}

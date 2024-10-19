use yew::prelude::*;
use gloo::net::http::Request;
use gloo::console::log;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value as JsonValue;
use chrono::DateTime;
use web_sys::HtmlTextAreaElement;
use crate::services::auth;
use crate::routes::Route;
use yew_router::prelude::*;


const NOTES_STORAGE_KEY: &str = "dashboard_notes";

#[derive(Clone, PartialEq)]
struct UserInfo {
    username: String,
    email: String,
    id: String,
    is_email_verified: bool,
    created_at: String,
}

pub enum DashboardMsg {
    FetchUserInfo,
    UserInfoFetched(Result<UserInfo, String>),
    UpdateNotes(String),
    SaveNotes,
    NotesSaved(Result<(), String>),
    Tick,
    Logout,
}

pub struct Dashboard {
    user_info: Option<UserInfo>,
    notes: String,
    error: Option<String>,
    timer: u32,
    _interval: Option<Interval>,
    navigator: Navigator,
}

impl Component for Dashboard {
    type Message = DashboardMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(DashboardMsg::FetchUserInfo);

        let navigator = ctx.link().navigator().unwrap();

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
                    Ok(info) => {
                        self.user_info = Some(info);
                        self.error = None;
                    }
                    Err(e) => {
                        self.error = Some(format!("Failed to fetch user info: {}", e));
                        log!("Error fetching user info: {}", e);
                    }
                }
                true
            }
            DashboardMsg::UpdateNotes(new_notes) => {
                self.notes = new_notes;
                true
            }
            DashboardMsg::SaveNotes => {
                let notes = self.notes.clone();
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = LocalStorage::set(NOTES_STORAGE_KEY, notes);
                    link.send_message(DashboardMsg::NotesSaved(result.map_err(|e| e.to_string())));
                });
                false
            }
            DashboardMsg::NotesSaved(result) => {
                match result {
                    Ok(_) => {
                        log!("Notes saved successfully");
                    }
                    Err(e) => {
                        self.error = Some(format!("Failed to save notes: {}", e));
                        log!("Error saving notes: {}", e);
                    }
                }
                true
            }
            DashboardMsg::Tick => {
                self.timer += 1;
                true
            }
            DashboardMsg::Logout => {
                auth::logout();
                self.navigator.push(&Route::Login);
                false
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let on_notes_change = ctx.link().callback(|e: InputEvent| {
            let input: HtmlTextAreaElement = e.target_unchecked_into();
            DashboardMsg::UpdateNotes(input.value())
        });

        let on_save_notes = ctx.link().callback(|_| DashboardMsg::SaveNotes);

        html! {
            <div class="dashboard-container">
                <header class="dashboard-header">
                    <h1>{ "Welcome to Your Dashboard 👋" }</h1>
                </header>

                <main class="dashboard-main" role="main">
                    { self.view_user_info() }
                    { self.view_notepad(on_notes_change, on_save_notes) }
                </main>

                { self.view_session_timer() }

                { self.view_error() }
            </div>
        }
    }
}

impl Dashboard {
    fn view_user_info(&self) -> Html {
        html! {
            <section class="section card user-info">
                <h2>{ "User Information 📋 " }</h2>
                {
                    if let Some(user) = &self.user_info {
                        html! {
                            <div class="info-grid">
                                { self.info_item("Username:  ", &user.username) }
                                { self.info_item("User ID:  ", &user.id) }
                                { self.info_item("Email:  ", &user.email) }
                                { self.info_item("Email Verified:  ", if user.is_email_verified { "Yes" } else { "No" }) }
                                { self.info_item("Account Created:  ", &user.created_at) }
                            </div>
                        }
                    } else {
                        html! { <p>{ "Loading user information..." }</p> }
                    }
                }
            </section>
        }
    }

    fn info_item(&self, label: &str, value: &str) -> Html {
        html! {
            <div class="info-item">
                <span class="info-label">{ label }</span>
                <span class="info-value">{ value }</span>
            </div>
        }
    }

    fn view_notepad(&self, on_notes_change: Callback<InputEvent>, on_save_notes: Callback<MouseEvent>) -> Html {
        html! {
            <section class="section card notepad">
                <h2>{ "Quick Notepad 📝" }</h2>
                <textarea
                    value={self.notes.clone()}
                    oninput={on_notes_change}
                />
                <button onclick={on_save_notes}>{ "Save Notes 💾" }</button>
            </section>
        }
    }

    fn view_session_timer(&self) -> Html {
        html! {
            <div class="card session-timer">
                <h2>{ "Session Timer ⏱️" }</h2>
                <p>{ format!("Time elapsed: {:02}:{:02}:{:02}", self.timer / 3600, (self.timer / 60) % 60, self.timer % 60) }</p>
            </div>
        }
    }

    fn view_error(&self) -> Html {
        if let Some(error) = &self.error {
            html! {
                <div class="error-message">
                    { error }
                </div>
            }
        } else {
            html! {}
        }
    }
}

async fn fetch_user_info() -> Result<UserInfo, String> {
    let token = auth::get_token().ok_or("No auth token found")?;

    log::debug!("Fetching user info with token: {}", token);

    let response = Request::get("/api/users/me")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| {
            log::error!("Network error: {:?}", e);
            format!("Network error: {}", e)
        })?;

    if response.status() != 200 {
        let error_message = format!("Server error: HTTP {}", response.status());
        log::error!("{}", error_message);
        return Err(error_message);
    }

    let data: JsonValue = response.json()
        .await
        .map_err(|e| {
            log::error!("Failed to parse response: {:?}", e);
            format!("Failed to parse response: {}", e)
        })?;

    log::debug!("Received user data: {:?}", data);
    Ok(UserInfo {
        username: data["username"].as_str().unwrap_or("N/A").to_string(),
        email: data["email"].as_str().unwrap_or("N/A").to_string(),
        id: data["id"].as_str().unwrap_or("N/A").to_string(),
        is_email_verified: data["is_email_verified"].as_bool().unwrap_or(false),
        created_at: data["created_at"].as_str()
            .and_then(|date_str| DateTime::parse_from_rfc3339(date_str).ok())
            .map(|date| date.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "N/A".to_string()),
    })
}
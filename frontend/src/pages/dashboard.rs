use web_sys::HtmlTextAreaElement;
use yew::prelude::*;
use gloo::net::http::Request;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value as JsonValue;
use chrono::DateTime;
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
                    Ok(user_info) => self.user_info = Some(user_info),
                    Err(error) => self.error = Some(error),
                }
                true
            }
            DashboardMsg::UpdateNotes(new_notes) => {
                self.notes = new_notes;
                false
            }
            DashboardMsg::SaveNotes => {
                let result = LocalStorage::set(NOTES_STORAGE_KEY, &self.notes);
                ctx.link().send_message(DashboardMsg::NotesSaved(result.map_err(|e| e.to_string())));
                false
            }
            DashboardMsg::NotesSaved(result) => {
                if let Err(error) = result {
                    self.error = Some(error);
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
        html! {
            <div class="dashboard">
                { self.view_user_info() }
                { self.view_notes(ctx) }
                { self.view_session_timer() }
                { self.view_error() }
                <button onclick={ctx.link().callback(|_| DashboardMsg::Logout)}>{ "Logout" }</button>
            </div>
        }
    }
}

impl Dashboard {
    fn view_user_info(&self) -> Html {
        if let Some(user_info) = &self.user_info {
            html! {
                <div class="user-info">
                    <h2>{ "User Info" }</h2>
                    <p>{ format!("Username: {}", user_info.username) }</p>
                    <p>{ format!("Email: {}", user_info.email) }</p>
                    <p>{ format!("Email Verified: {}", user_info.is_email_verified) }</p>
                    <p>{ format!("Account Created At: {}", user_info.created_at) }</p>
                </div>
            }
        } else {
            html! {
                <p>{ "Loading user info..." }</p>
            }
        }
    }

    fn view_notes(&self, ctx: &Context<Self>) -> Html {
        let oninput = ctx.link().callback(|e: InputEvent| {
            let input: HtmlTextAreaElement = e.target_unchecked_into();
            DashboardMsg::UpdateNotes(input.value())
        });

        html! {
            <div class="notes-section">
                <h2>{ "Notes" }</h2>
                <textarea value={self.notes.clone()} {oninput} />
                <button onclick={ctx.link().callback(|_| DashboardMsg::SaveNotes)}>{ "Save Notes" }</button>
            </div>
        }
    }

    fn view_session_timer(&self) -> Html {
        html! {
            <div class="session-timer">
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
        .map_err(|e| format!("Network error: {}", e))?;

    if response.status() != 200 {
        return Err(format!("Server error: HTTP {}", response.status()));
    }

    let data: JsonValue = response.json().await.map_err(|e| format!("Failed to parse response: {}", e))?;

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

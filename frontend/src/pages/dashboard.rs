use web_sys::HtmlTextAreaElement;
use yew::prelude::*;
use gloo::storage::{LocalStorage, Storage};
use gloo::timers::callback::Interval;
use wasm_bindgen_futures::spawn_local;
use serde::{Deserialize};
use crate::services::auth;
use crate::routes::Route;
use yew_router::prelude::*;
use gloo::console::log;

const NOTES_STORAGE_KEY: &str = "dashboard_notes";

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
    Logout,
}

pub struct Dashboard {
    user_info: Option<User>,
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
        // Start fetching user info immediately
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
                    Ok(user_info) => {
                        self.error = None;
                        self.user_info = Some(user_info);
                    }
                    Err(error) => {
                        self.error = Some(error.clone());  // Clone the error if needed
                        // If unauthorized, redirect to login
                        if error.contains("unauthorized") {
                            let navigator = self.navigator.clone();  // Clone the navigator
                            navigator.push(&Route::Login);
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
            DashboardMsg::Logout => {
                auth::logout();
                self.navigator.push(&Route::Login);
                false
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="dashboard-container">
                <div class="dashboard-content">
                    <div class="dashboard-header">
                        <h1>{"Dashboard"}</h1>
                    </div>

                    if let Some(error) = &self.error {
                        <div class="error-banner">
                            {error}
                        </div>
                    }

                    <div class="dashboard-grid">
                        <div class="user-info-card">
                            <h2>{"User Info"}</h2>
                            if let Some(user) = &self.user_info {
                                <div class="info-row">
                                    <span class="info-label">{"Username:"}</span>
                                    {&user.username}
                                </div>
                                <div class="info-row">
                                    <span class="info-label">{"Email:"}</span>
                                    {user.email.as_deref().unwrap_or("Not provided")}
                                </div>
                                <div class="info-row">
                                    <span class="info-label">{"Email Status:"}</span>
                                    <span class={if user.is_email_verified { "status-verified" } else { "status-unverified" }}>
                                        {if user.is_email_verified { "Verified" } else { "Not Verified" }}
                                    </span>
                                </div>
                            } else {
                                <div class="loading-spinner">{"Loading user info..."}</div>
                            }
                            <div class="info-row">
                                <span class="info-label">{"Session Time:"}</span>
                                {format!("{:02}:{:02}:{:02}",
                                    self.timer / 3600,
                                    (self.timer / 60) % 60,
                                    self.timer % 60
                                )}
                            </div>
                        </div>

                        <div class="notes-card">
                            <h2>{"Notes"}</h2>
                            <textarea
                                class="notes-textarea"
                                placeholder="Write your notes here..."
                                value={self.notes.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input: HtmlTextAreaElement = e.target_unchecked_into();
                                    DashboardMsg::UpdateNotes(input.value())
                                })}
                            />
                            <button
                                onclick={ctx.link().callback(|_| DashboardMsg::SaveNotes)}
                                class="save-button">
                                {"Save Notes"}
                            </button>
                        </div>
                    </div>
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
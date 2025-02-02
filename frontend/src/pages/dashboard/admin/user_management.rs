use yew::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use crate::services::auth;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserListResponse {
    users: Vec<UserAdminView>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserAdminView {
    id: String,
    username: String,
    email: Option<String>,
    role: String,
    is_email_verified: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserAdminView {
    fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub enum Msg {
    FetchUsers,
    UsersFetched(Result<Vec<UserAdminView>, String>),
}

pub struct UserManagement {
    users: Vec<UserAdminView>,
    error: Option<String>,
}

impl Component for UserManagement {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        ctx.link().send_message(Msg::FetchUsers);
        Self {
            users: Vec::new(),
            error: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::FetchUsers => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = fetch_users().await;
                    link.send_message(Msg::UsersFetched(result));
                });
                false
            }
            Msg::UsersFetched(result) => {
                match result {
                    Ok(users) => {
                        self.error = None;
                        self.users = users;
                    }
                    Err(error) => {
                        self.error = Some(error);
                    }
                }
                true
            }
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"User Management"}</h2>
                    if let Some(error) = &self.error {
                        <div class="c-validation__error">
                            {error}
                        </div>
                    }
                    <div class="c-table-container">
                        <table class="c-table">
                            <thead>
                                <tr>
                                    <th>{"Username"}</th>
                                    <th>{"Email"}</th>
                                    <th>{"Email Status"}</th>
                                    <th>{"Role"}</th>
                                    <th>{"Created At"}</th>
                                    <th>{"Actions"}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {
                                    if !self.users.is_empty() {
                                        self.users.iter().map(|user| {
                                            html! {
                                                <tr key={user.id.clone()}>
                                                    <td>{&user.username}</td>
                                                    <td>{user.email.as_deref().unwrap_or("Not provided")}</td>
                                                    <td>
                                                        <span class={classes!("c-badge", if user.is_email_verified { "c-badge--success" } else { "c-badge--warning" })}>
                                                            {if user.is_email_verified { "Verified" } else { "Unverified" }}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <span class={classes!("c-badge", if user.is_admin() { "c-badge--primary" } else { "c-badge--secondary" })}>
                                                            {&user.role}
                                                        </span>
                                                    </td>
                                                    <td>{user.created_at.format("%Y-%m-%d %H:%M:%S").to_string()}</td>
                                                    <td class="c-table__actions">
                                                        <button class="c-button c-button--small c-button--info" title="Inspect user">
                                                            {"Inspect"}
                                                        </button>
                                                        <button class="c-button c-button--small c-button--warning" title="Edit user">
                                                            {"Edit"}
                                                        </button>
                                                        <button class="c-button c-button--small c-button--danger" title="Delete user">
                                                            {"Delete"}
                                                        </button>
                                                    </td>
                                                </tr>
                                            }
                                        }).collect::<Html>()
                                    } else {
                                        html! {
                                            <tr>
                                                <td colspan="6" class="c-table__empty">
                                                    {"Loading user data..."}
                                                </td>
                                            </tr>
                                        }
                                    }
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        }
    }
}

async fn fetch_users() -> Result<Vec<UserAdminView>, String> {
    let token = auth::get_token().ok_or("No auth token found")?;

    let response = gloo::net::http::Request::get("/api/admin/users")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e.to_string()))?;

    if !response.ok() {
        return Err(format!("Failed to fetch users: {}", response.status()));
    }

    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e))?;

    let api_response: ApiResponse<UserListResponse> = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if !api_response.success {
        return Err(api_response.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }

    match api_response.data {
        Some(user_list) => Ok(user_list.users),
        None => Err("No user data in response".to_string()),
    }
}

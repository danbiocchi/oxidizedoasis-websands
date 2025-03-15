use yew::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use crate::services::auth;
use crate::services::request::{RequestInterceptor, RequestBuilderExt};
use chrono::{DateTime, Utc};
use gloo::console::log;

// Import necessary types for event handling
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{CustomEvent, Event, HtmlInputElement, HtmlSelectElement};

#[derive(Debug, Clone, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserDetailResponse {
    // This struct is now directly the UserDetail
}

#[derive(Debug, Clone, Deserialize)]
struct UserDetail {
    id: String,
    username: String,
    email: Option<String>,
    role: String,
    is_email_verified: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    // Additional fields that might be available in the detailed view
    last_login: Option<DateTime<Utc>>,
    login_count: Option<i32>,
}

#[derive(Properties, PartialEq)]
pub struct UserDetailProps {
    pub user_id: String,
    pub mode: String, // "inspect" or "edit"
}

pub enum Msg {
    FetchUserDetail,
    UserDetailFetched(Result<UserDetail, String>),
    UpdateField(String, String),
    SaveUser,
    UserSaved(Result<(), String>),
    GoBack,
}

pub struct UserDetailComponent {
    user_id: String,
    mode: String,
    user_detail: Option<UserDetail>,
    error: Option<String>,
    success_message: Option<String>,
    is_loading: bool,
    edited_fields: std::collections::HashMap<String, String>,
}

impl Component for UserDetailComponent {
    type Message = Msg;
    type Properties = UserDetailProps;

    fn create(ctx: &Context<Self>) -> Self {
        let user_id = ctx.props().user_id.clone();
        ctx.link().send_message(Msg::FetchUserDetail);
        
        Self {
            user_id,
            mode: ctx.props().mode.clone(),
            user_detail: None,
            error: None,
            success_message: None,
            is_loading: true,
            edited_fields: std::collections::HashMap::new(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::FetchUserDetail => {
                self.is_loading = true;
                let user_id = self.user_id.clone();
                let link = ctx.link().clone();
                
                spawn_local(async move {
                    let result = fetch_user_detail(&user_id).await;
                    link.send_message(Msg::UserDetailFetched(result));
                });
                
                false
            }
            Msg::UserDetailFetched(result) => {
                self.is_loading = false;
                match result {
                    Ok(user_detail) => {
                        self.error = None;
                        self.user_detail = Some(user_detail);
                    }
                    Err(error) => {
                        self.error = Some(error);
                    }
                }
                true
            }
            Msg::UpdateField(field, value) => {
                self.edited_fields.insert(field, value);
                true
            }
            Msg::SaveUser => {
                if self.mode != "edit" {
                    return false;
                }
                
                self.is_loading = true;
                let user_id = self.user_id.clone();
                let edited_fields = self.edited_fields.clone();
                let link = ctx.link().clone();
                
                spawn_local(async move {
                    let result = save_user(&user_id, &edited_fields).await;
                    link.send_message(Msg::UserSaved(result));
                });
                
                false
            }
            Msg::UserSaved(result) => {
                self.is_loading = false;
                match result {
                    Ok(_) => {
                        self.success_message = Some("User updated successfully".to_string());
                        self.error = None;
                        // Refresh user details
                        ctx.link().send_message(Msg::FetchUserDetail);
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.success_message = None;
                    }
                }
                true
            }
            Msg::GoBack => {
                // Create a CustomEvent with options to set detail
                let mut options = web_sys::CustomEventInit::new();
                options.detail(&JsValue::from_str("UserManagement"));
                
                log!("UserDetail: Creating GoBack event to return to UserManagement");
                let event = CustomEvent::new_with_event_init_dict(
                    "changeView", 
                    &options
                ).unwrap();
                
                web_sys::window()
                    .map(|window| {
                        match window.dispatch_event(&event)
 {
                            Ok(_) => log!("UserDetail: Successfully dispatched GoBack event"),
                            Err(e) => log!("UserDetail: Error dispatching event: {:?}", e),
                        }
                    })
                    .unwrap_or_else(|| log!("UserDetail: Window not available"));

                
                false
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let is_edit_mode = self.mode == "edit";
        let mode_display = if is_edit_mode { "Edit" } else { "Inspect" };
        
        html! {
            <div class="l-grid l-grid--dashboard c-user-detail-enter">
                <div class="c-card c-card--dashboard c-card--user-detail">
                    <div class="c-user-detail__header">
                        <div class="c-breadcrumbs">
                            <span class="c-breadcrumbs__item" onclick={ctx.link().callback(|_| Msg::GoBack)}>
                                {"User Management"}
                            </span>
                            <span class="c-breadcrumbs__separator">{" > "}</span>
                            <span class="c-breadcrumbs__item c-breadcrumbs__item--active">
                                {
                                    if let Some(user) = &self.user_detail {
                                        format!("{} {}", mode_display, user.username)
                                    } else {
                                        format!("User {}", mode_display)
                                    }
                                }
                            </span>
                        </div>
                        
                        <h2 class="c-user-detail__title">
                            <svg class="c-user-detail__title-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>
                            </svg>
                            {
                                if let Some(user) = &self.user_detail {
                                    format!("{} User: {}", mode_display, user.username)
                                } else {
                                    format!("{} User", mode_display)
                                }
                            }
                        </h2>
                    </div>
                    
                    <div class="c-user-detail__content">
                        {
                            if let Some(error) = &self.error {
                                html! {
                                    <div class="c-validation__error--user-detail">
                                        <svg class="c-validation__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>
                                        </svg>
                                        {error}
                                    </div>
                                }
                            } else {
                                html! { <></> }
                            }
                        }
                        
                        {
                            if let Some(message) = &self.success_message {
                                html! {
                                    <div class="c-validation__success--user-detail">
                                        <svg class="c-validation__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
                                        </svg>
                                        {message}
                                    </div>
                                }
                            } else {
                                html! { <></> }
                            }
                        }
                        
                        {
                            if self.is_loading {
                                html! {
                                    <div class="c-loader--user-detail">
                                        <div class="c-loader__spinner"></div>
                                        {"Loading user details..."}
                                    </div>
                                }
                            } else if let Some(user) = &self.user_detail {
                                self.render_user_form(ctx, user, is_edit_mode)
                            } else {
                                html! {
                                    <div class="c-table__empty">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="12" r="10"></circle>
                                            <line x1="12" y1="8" x2="12" y2="12"></line>
                                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                        </svg>
                                        <p>{"No user data available"}</p>
                                    </div>
                                }
                            }
                        }
                    </div>
                </div>
            </div>
        }
    }
}

impl UserDetailComponent {
    fn render_user_form(&self, ctx: &Context<Self>, user: &UserDetail, is_edit_mode: bool) -> Html {
        html! {
            <div class="c-form c-form--user-detail">
                <div class="c-form__section">
                    <div class="c-form__section-title">{"User Information"}</div>
                    <div class="c-form__row">
                        <div class="c-form__group">
                            <label class="c-form__label">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>
                                </svg>
                                {"User ID"}
                            </label>
                            <input
                                type="text"
                                class="c-form__input c-form__input--user-detail"
                                value={user.id.clone()} 
                                disabled=true
                            />
                        </div>
                        
                        <div class="c-form__group">
                            <label class="c-form__label">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>
                                </svg>
                                {"Username"}
                            </label>
                            <input 
                                type="text" 
                                class="c-form__input c-form__input--user-detail" 
                                value={
                                    self.edited_fields.get("username")
                                        .cloned()
                                        .unwrap_or_else(|| user.username.clone())
                                } 
                                disabled={!is_edit_mode}
                                onchange={
                                    if is_edit_mode {
                                        ctx.link().callback(|e: Event| {
                                            let input: HtmlInputElement = e.target_unchecked_into();
                                            Msg::UpdateField("username".to_string(), input.value())
                                        })
                                    } else {
                                        Callback::noop()
                                    }
                                }
                            />
                        </div>
                    </div>
                    
                    <div class="c-form__row">
                        <div class="c-form__group">
                            <label class="c-form__label">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline>
                                </svg>
                                {"Email"}
                            </label>
                            <input 
                                type="email" 
                                class="c-form__input c-form__input--user-detail" 
                                value={
                                    self.edited_fields.get("email")
                                        .cloned()
                                        .unwrap_or_else(|| user.email.clone().unwrap_or_default())
                                } 
                                disabled={!is_edit_mode}
                                onchange={
                                    if is_edit_mode {
                                        ctx.link().callback(|e: Event| {
                                            let input: HtmlInputElement = e.target_unchecked_into();
                                            Msg::UpdateField("email".to_string(), input.value())
                                        })
                                    } else {
                                        Callback::noop()
                                    }
                                }
                            />
                        </div>
                    </div>
                </div>
                
                <div class="c-form__section">
                    <div class="c-form__section-title">{"Account Settings"}</div>
                    <div class="c-form__row">
                        <div class="c-form__group">
                            <label class="c-form__label">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                </svg>
                                {"Role"}
                            </label>
                            <select 
                                class="c-form__select c-form__select--user-detail" 
                                disabled={!is_edit_mode}
                                onchange={
                                    if is_edit_mode {
                                        ctx.link().callback(|e: Event| {
                                            let select: HtmlSelectElement = e.target_unchecked_into();
                                            Msg::UpdateField("role".to_string(), select.value())
                                        })
                                    } else {
                                        Callback::noop()
                                    }
                                }
                            >
                                <option 
                                    value="user" 
                                    selected={
                                        self.edited_fields.get("role")
                                            .cloned()
                                            .unwrap_or_else(|| user.role.clone()) == "user"
                                    }
                                >
                                    {"User"}
                                </option>
                                <option 
                                    value="admin" 
                                    selected={
                                        self.edited_fields.get("role")
                                            .cloned()
                                            .unwrap_or_else(|| user.role.clone()) == "admin"
                                    }
                                >
                                    {"Admin"}
                                </option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="c-form__group">
                        <label class="c-form__label">
                            <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
                            </svg>
                            {"Email Verification Status"}
                        </label>
                        <div class="c-form__static">
                            <span class={classes!(
                                "c-badge--enhanced", 
                                if user.is_email_verified { "c-badge--verified" } else { "c-badge--unverified" }
                            )}>
                                <svg class="c-badge-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    {if user.is_email_verified { 
                                        html! { 
                                            <>
                                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                                <polyline points="22 4 12 14.01 9 11.01"></polyline>
                                            </> 
                                        } 
                                    } else { 
                                        html! { 
                                            <>
                                                <circle cx="12" cy="12" r="10"></circle>
                                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                            </> 
                                        } 
                                    }}
                                </svg>
                                {if user.is_email_verified { "Verified" } else { "Unverified" }}
                            </span>
                        </div>
                    </div>
                    
                    <div class="c-form__group">
                        <label class="c-form__label">
                            <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            {"Created At"}
                        </label>
                        <div class="c-form__static c-timestamp">
                            <svg class="c-timestamp__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line>
                            </svg>
                            <span>{user.created_at.format("%Y-%m-%d %H:%M:%S").to_string()}</span>
                        </div>
                    </div>
                    
                    <div class="c-form__group">
                        <label class="c-form__label">
                            <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            {"Updated At"}
                        </label>
                        <div class="c-form__static c-timestamp">
                            <svg class="c-timestamp__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line>
                            </svg>
                            <span>{user.updated_at.format("%Y-%m-%d %H:%M:%S").to_string()}</span>
                        </div>
                    </div>
                    
                    {
                        if let Some(last_login) = &user.last_login {
                            html! {
                                <div class="c-form__group">
                                    <label class="c-form__label">
                                        <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
                                            <polyline points="10 17 15 12 10 7"></polyline>
                                            <line x1="15" y1="12" x2="3" y2="12"></line>
                                        </svg>
                                        {"Last Login"}
                                    </label>
                                    <div class="c-form__static c-timestamp">
                                        {last_login.format("%Y-%m-%d %H:%M:%S").to_string()}
                                    </div>
                                </div>
                            }
                        } else {
                            html! { <></> }
                        }
                    }
                    
                    {
                        if let Some(login_count) = user.login_count {
                            html! {
                                <div class="c-form__group">
                                    <label class="c-form__label">
                                        <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M18 8h1a4 4 0 0 1 0 8h-1"></path>
                                            <path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"></path>
                                            <line x1="6" y1="1" x2="6" y2="4"></line>
                                            <line x1="10" y1="1" x2="10" y2="4"></line>
                                            <line x1="14" y1="1" x2="14" y2="4"></line>
                                        </svg>
                                        {"Login Count"}
                                    </label>
                                    <div class="c-form__value">
                                        {login_count.to_string()}
                                    </div>
                                </div>
                            }
                        } else {
                            html! { <></> }
                        }
                    }
                    
                    <div class="c-form__actions">
                        <button 
                            class="c-button c-button--secondary-user-detail c-button--user-detail" 
                            onclick={ctx.link().callback(|_| Msg::GoBack)}
                        >
                            <svg class="c-button__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <line x1="19" y1="12" x2="5" y2="12"></line>
                                <polyline points="12 19 5 12 12 5"></polyline>
                            </svg>
                            {"Back to User Management"}
                        </button>
                        
                        {
                            if is_edit_mode {
                                html! {
                                    <button 
                                        class="c-button c-button--primary-user-detail c-button--user-detail" 
                                        onclick={ctx.link().callback(|_| Msg::SaveUser)}
                                        disabled={self.is_loading}
                                    >
                                        <svg class="c-button__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path>
                                            <polyline points="17 21 17 13 7 13 7 21"></polyline>
                                            <polyline points="7 3 7 8 15 8"></polyline>
                                        </svg>
                                        {"Save Changes"}
                                    </button>
                                }
                            } else {
                                html! { <></> }
                            }
                        }
                    </div>
                </div>
            </div>
        }
    }
}

async fn fetch_user_detail(user_id: &str) -> Result<UserDetail, String> {
    let url = format!("/api/cookie/admin/users/{}", user_id);
    let request = RequestInterceptor::get(&url);

    log!("UserDetail: Fetching user details for ID: {}", user_id);
    
    
    // Use send() for now, as we're having issues with send_with_retry()
    log!("UserDetail: Sending request to {}", url);
    let response = request.send().await.map_err(|e| e.to_string())?;
    
    if !response.ok() {
        let status = response.status();
        return Err(format!("Failed to fetch user details: {}", status));
    }
    
    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e))?;
    
    log!("UserDetail: Response received: {}", &response_text);
    
    let api_response: ApiResponse<UserDetail> = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if !api_response.success {
        return Err(api_response.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }
    
    match api_response.data {
        Some(user_detail) => Ok(user_detail),
        None => Err("No user data in response".to_string())
    }
}

async fn save_user(user_id: &str, edited_fields: &std::collections::HashMap<String, String>) -> Result<(), String> {
    let url = format!("/api/cookie/admin/users/{}", user_id);
    
    // Create a JSON object with the edited fields
    let mut json_data = serde_json::Map::new();
    for (key, value) in edited_fields {
        json_data.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    
    let request = RequestInterceptor::put(&url)
        .json(&serde_json::Value::Object(json_data))
        .map_err(|e| format!("Failed to create request: {}", e))?;
    log!("UserDetail: Sending save request to {}", url);
    
    // Use send() for now, as we're having issues with send_with_retry()
    let response = request.send().await.map_err(|e| e.to_string())?;

    if !response.ok() {
        let status = response.status();
        return Err(format!("Failed to update user: {}", status));
    }
    
    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e))?;
    
    log!("UserDetail: Update response: {}", &response_text);
    
    let api_response: ApiResponse<()> = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if !api_response.success {
        return Err(api_response.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }
    
    Ok(())
}
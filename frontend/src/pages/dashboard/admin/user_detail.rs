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
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <div class="c-breadcrumbs">
                        <span class="c-breadcrumbs__item" onclick={ctx.link().callback(|_| Msg::GoBack)}>
                            {"User Management"}
                        </span>
                        <span class="c-breadcrumbs__separator">{" > "}</span>
                        <span class="c-breadcrumbs__item c-breadcrumbs__item--active">
                            {
                                if let Some(user) = &self.user_detail {
                                    format!("{} {}", user.username, mode_display)
                                } else {
                                    format!("User {}", mode_display)
                                }
                            }
                        </span>
                    </div>
                    
                    <h2 class="c-card__title">
                        {
                            if let Some(user) = &self.user_detail {
                                format!("{} User: {}", mode_display, user.username)
                            } else {
                                format!("{} User", mode_display)
                            }
                        }
                    </h2>
                    
                    if let Some(error) = &self.error {
                        <div class="c-validation__error">
                            {error}
                        </div>
                    }
                    
                    if let Some(message) = &self.success_message {
                        <div class="c-validation__success">
                            {message}
                        </div>
                    }
                    
                    if self.is_loading {
                        <div class="c-loader">{"Loading..."}</div>
                    } else if let Some(user) = &self.user_detail {
                        <div class="c-form">
                            <div class="c-form__group">
                                <label class="c-form__label">{"User ID"}</label>
                                <input 
                                    type="text" 
                                    class="c-form__input" 
                                    value={user.id.clone()} 
                                    disabled=true
                                />
                            </div>
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Username"}</label>
                                <input 
                                    type="text" 
                                    class="c-form__input" 
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
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Email"}</label>
                                <input 
                                    type="email" 
                                    class="c-form__input" 
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
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Role"}</label>
                                <select 
                                    class="c-form__select" 
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
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Email Verification Status"}</label>
                                <div class="c-form__static">
                                    <span class={classes!(
                                        "c-badge", 
                                        if user.is_email_verified { "c-badge--success" } else { "c-badge--warning" }
                                    )}>
                                        {if user.is_email_verified { "Verified" } else { "Unverified" }}
                                    </span>
                                </div>
                            </div>
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Created At"}</label>
                                <div class="c-form__static">
                                    {user.created_at.format("%Y-%m-%d %H:%M:%S").to_string()}
                                </div>
                            </div>
                            
                            <div class="c-form__group">
                                <label class="c-form__label">{"Updated At"}</label>
                                <div class="c-form__static">
                                    {user.updated_at.format("%Y-%m-%d %H:%M:%S").to_string()}
                                </div>
                            </div>
                            
                            if let Some(last_login) = &user.last_login {
                                <div class="c-form__group">
                                    <label class="c-form__label">{"Last Login"}</label>
                                    <div class="c-form__static">
                                        {last_login.format("%Y-%m-%d %H:%M:%S").to_string()}
                                    </div>
                                </div>
                            }
                            
                            if let Some(login_count) = user.login_count {
                                <div class="c-form__group">
                                    <label class="c-form__label">{"Login Count"}</label>
                                    <div class="c-form__static">
                                        {login_count.to_string()}
                                    </div>
                                </div>
                            }
                            
                            <div class="c-form__actions">
                                <button 
                                    class="c-button c-button--secondary" 
                                    onclick={ctx.link().callback(|_| Msg::GoBack)}
                                >
                                    {"Back to User Management"}
                                </button>
                                
                                if is_edit_mode {
                                    <button 
                                        class="c-button c-button--primary" 
                                        onclick={ctx.link().callback(|_| Msg::SaveUser)}
                                        disabled={self.is_loading}
                                    >
                                        {"Save Changes"}
                                    </button>
                                }
                            </div>
                        </div>
                    } else {
                        <div class="c-table__empty">
                            {"No user data available"}
                        </div>
                    }
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
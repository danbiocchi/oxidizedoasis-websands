use yew::prelude::*;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use crate::services::auth;
use crate::pages::dashboard::DashboardView;
use crate::services::request::{RequestInterceptor, RequestBuilderExt};
use chrono::{DateTime, Utc};
use gloo::console::log;

// Import necessary types for event handling
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{CustomEvent, InputEvent};

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
    #[allow(dead_code)]
    fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub enum Msg {
    FetchUsers,
    UsersFetched(Result<Vec<UserAdminView>, String>),
    FetchCurrentUser,
    CurrentUserFetched(Result<String, String>),
    InspectUser(String),
    EditUser(String),
    DeleteUser(String),
    UpdateDeleteConfirmation(String),
    ConfirmDelete,
    CancelDelete,
    UserDeleted(Result<(), String>),
}

pub struct UserManagement {
    users: Vec<UserAdminView>,
    error: Option<String>,
    success_message: Option<String>,
    delete_user_id: Option<String>,
    delete_user_name: Option<String>,
    show_delete_modal: bool,
    delete_confirmation_text: String,
    is_loading: bool,
    current_user_id: Option<String>,
}

impl Component for UserManagement {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        // Fetch users and current user ID
        ctx.link().send_message(Msg::FetchUsers);
        ctx.link().send_message(Msg::FetchCurrentUser);
        
        Self {
            users: Vec::new(),
            error: None,
            success_message: None,
            delete_user_id: None,
            delete_user_name: None,
            show_delete_modal: false,
            delete_confirmation_text: String::new(),
            is_loading: false,
            current_user_id: None,
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
            Msg::FetchCurrentUser => {
                let link = ctx.link().clone();
                spawn_local(async move {
                    let result = fetch_current_user_id().await;
                    link.send_message(Msg::CurrentUserFetched(result));
                });
                false
            }
            Msg::CurrentUserFetched(result) => {
                match result {
                    Ok(user_id) => {
                        self.current_user_id = Some(user_id);
                    }
                    Err(error) => {
                        log!("Failed to fetch current user ID: {}", error);
                        // Don't set an error message for this, as it's not critical for the UI
                    }
                }
                true
            }
            Msg::InspectUser(user_id) => {
                // Emit a custom event to change the view to UserInspect
                // Create a CustomEvent with options to set detail
                let mut options = web_sys::CustomEventInit::new();
                options.set_detail(&JsValue::from_str(&format!("UserInspect:{}", user_id)));
                log!("UserManagement: Creating UserInspect event with ID: {}", user_id);
                
                let event = CustomEvent::new_with_event_init_dict(
                    "changeView", 
                    &options
                ).unwrap();
                
                web_sys::window()
                    .map(|window| {
                        match window.dispatch_event(&event) {
                            Ok(_) => log!("UserManagement: Successfully dispatched UserInspect event"),
                            Err(e) => log!("UserManagement: Error dispatching event: {:?}", e),
                        }
                    })
                    .unwrap_or_else(|| log!("UserManagement: Window not available"));


                false
            }
            Msg::EditUser(user_id) => {
                // Emit a custom event to change the view to UserEdit
                // Create a CustomEvent with options to set detail
                let mut options = web_sys::CustomEventInit::new();
                options.set_detail(&JsValue::from_str(&format!("UserEdit:{}", user_id)));
                log!("UserManagement: Creating UserEdit event with ID: {}", user_id);
                
                let event = CustomEvent::new_with_event_init_dict(
                    "changeView", 
                    &options
                ).unwrap();
                
                web_sys::window()
                    .map(|window| {
                        match window.dispatch_event(&event)
 {
                 Ok(_) => log!("UserManagement: Successfully dispatched UserEdit event"),
                            Err(e) => log!("UserManagement: Error dispatching event: {:?}", e),
                        }
                    })
                    .unwrap_or_else(|| log!("UserManagement: Window not available"));           
                false
            }
            Msg::DeleteUser(user_id) => {
                // Find the user name for the confirmation dialog
                let user_name = self.users.iter()
                    .find(|u| u.id == user_id)
                    .map(|u| u.username.clone())
                    .unwrap_or_else(|| "Unknown User".to_string());
                
                self.delete_user_id = Some(user_id);
                self.delete_user_name = Some(user_name);
                self.show_delete_modal = true;
                self.delete_confirmation_text = String::new();
                true
            }
            Msg::UpdateDeleteConfirmation(text) => {
                self.delete_confirmation_text = text;
                true
            }
            Msg::ConfirmDelete => {
                if self.delete_confirmation_text != "DELETE" {
                    self.error = Some("Please type DELETE to confirm".to_string());
                    return true;
                }
                
                if let Some(user_id) = self.delete_user_id.clone() {
                    self.is_loading = true;
                    self.error = None;
                    let link = ctx.link().clone();
                    
                    spawn_local(async move {
                        let result = delete_user(&user_id).await;
                        link.send_message(Msg::UserDeleted(result));
                    });
                }
                
                false
            }
            Msg::CancelDelete => {
                self.show_delete_modal = false;
                self.delete_user_id = None;
                self.delete_user_name = None;
                self.delete_confirmation_text = String::new();
                self.error = None;
                true
            }
            Msg::UserDeleted(result) => {
                self.is_loading = false;
                self.show_delete_modal = false;
                
                match result {
                    Ok(_) => {
                        self.success_message = Some("User deleted successfully".to_string());
                        self.error = None;
                        // Refresh the user list
                        ctx.link().send_message(Msg::FetchUsers);
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.success_message = None;
                    }
                }
                
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"User Management"}</h2>
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
                                            let user_id_inspect = user.id.clone();
                                            let user_id_edit = user.id.clone();
                                            let user_id_delete = user.id.clone();
                                            
                                            // Check if this is the current user
                                            let is_current_user = self.current_user_id.as_ref()
                                                .map(|current_id| current_id == &user.id)
                                                .unwrap_or(false);
                                            
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
                                                            {user.role.clone()}
                                                        </span>
                                                    </td>
                                                    <td>{user.created_at.format("%Y-%m-%d %H:%M:%S").to_string()}</td>
                                                    <td class="c-table__actions">
                                                        <button 
                                                            class="c-button c-button--small c-button--info" 
                                                            title="Inspect user"
                                                            onclick={ctx.link().callback(move |_| Msg::InspectUser(user_id_inspect.clone()))}
                                                        >
                                                            {"Inspect"}
                                                        </button>
                                                        <button 
                                                            class="c-button c-button--small c-button--warning" 
                                                            title={if is_current_user { "You cannot edit your own account" } else { "Edit user" }}
                                                            onclick={ctx.link().callback(move |_| Msg::EditUser(user_id_edit.clone()))}
                                                            disabled={is_current_user}
                                                        >
                                                            {"Edit"}
                                                        </button>
                                                        <button 
                                                            class="c-button c-button--small c-button--danger" 
                                                            title={if is_current_user { "You cannot delete your own account" } else { "Delete user" }}
                                                            onclick={ctx.link().callback(move |_| Msg::DeleteUser(user_id_delete.clone()))}
                                                            disabled={is_current_user}
                                                        >
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
                    
                    // Delete confirmation modal
                    if self.show_delete_modal {
                        <div class="c-modal">
                            <div class="c-modal__overlay" onclick={ctx.link().callback(|_| Msg::CancelDelete)}></div>
                            <div class="c-modal__container c-modal--danger">
                                <div class="c-modal__header">
                                    <h3 class="c-modal__title">{"Confirm Delete"}</h3>
                                    <button 
                                        class="c-modal__close" 
                                        onclick={ctx.link().callback(|_| Msg::CancelDelete)}
                                        aria-label="Close"
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <line x1="18" y1="6" x2="6" y2="18"></line>
                                            <line x1="6" y1="6" x2="18" y2="18"></line>
                                        </svg>
                                    </button>
                                </div>
                                <div class="c-modal__body">
                                    <p class="c-modal__text">
                                        {format!("Are you sure you want to delete user {}?", self.delete_user_name.clone().unwrap_or_default())}
                                    </p>
                                    <p class="c-modal__text c-modal__text--warning">
                                        {"This action cannot be undone. Please type DELETE to confirm."}
                                    </p>
                                    <div class="c-form__group">
                                        <input 
                                            type="text" 
                                            class="c-form__input c-form__input--user-detail" 
                                            placeholder="Type DELETE to confirm"
                                            value={self.delete_confirmation_text.clone()}
                                            oninput={ctx.link().callback(|e: InputEvent| {
                                                let input = e.target_unchecked_into::<web_sys::HtmlInputElement>();
                                                Msg::UpdateDeleteConfirmation(input.value())
                                            })}
                                        />
                                    </div>
                                </div>
                                <div class="c-modal__footer">
                                    <button 
                                        class="c-button c-button--secondary-user-detail c-button--user-detail" 
                                        onclick={ctx.link().callback(|_| Msg::CancelDelete)}
                                        disabled={self.is_loading}
                                    >
                                        {"Cancel"}
                                    </button>
                                    <button 
                                        class="c-button c-button--danger c-button--user-detail" 
                                        onclick={ctx.link().callback(|_| Msg::ConfirmDelete)}
                                        disabled={self.is_loading || self.delete_confirmation_text != "DELETE"}
                                    >
                                        {if self.is_loading { "Deleting..." } else { "Yes, Delete" }}
                                    </button>
                                </div>
                            </div>
                        </div>
                    }
                </div>
            </div>
        }
    }
}

impl Default for UserManagement {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            error: None,
            success_message: None,
            delete_user_id: None,
            delete_user_name: None,
            show_delete_modal: false,
            delete_confirmation_text: String::new(),
            is_loading: false,
            current_user_id: None,
        }
    }
}

async fn fetch_users() -> Result<Vec<UserAdminView>, String> {
    // Use the RequestInterceptor to handle token refresh and CSRF token automatically
    let request = RequestInterceptor::get("/api/cookie/admin/users");
    let response = request.send_with_retry().await?;

    // Check if the response is successful
    if !response.ok() {
        // If we still get unauthorized after the RequestInterceptor's automatic retry,
        // it means we don't have admin privileges
        let status = response.status();
        if status == 401 {
            auth::remove_tokens(); // Clear tokens as they might be invalid
            return Err("Unauthorized access. Please log in again.".to_string());
        } else if status == 403 {
            return Err("Access forbidden. You don't have admin privileges.".to_string());
        } else {
            return Err(format!("Failed to fetch users: {}", status));
        }
    }
    
    // Process successful response
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

async fn delete_user(user_id: &str) -> Result<(), String> {
    let url = format!("/api/cookie/admin/users/{}", user_id);
    let request = RequestInterceptor::delete(&url);
    let response = request.send_with_retry().await?;
    
    if !response.ok() {
        let status = response.status();
        return Err(format!("Failed to delete user: {}", status));
    }
    
    let response_text = response.text().await
        .map_err(|e| format!("Failed to get response text: {}", e))?;
    
    let api_response: ApiResponse<()> = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if !api_response.success {
        return Err(api_response.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }
    
    Ok(())
}

// Function to fetch the current user's ID
async fn fetch_current_user_id() -> Result<String, String> {
    // Use the RequestInterceptor to handle token refresh automatically
    let response = RequestInterceptor::get("/api/cookie/users/me")
        .send_with_retry()
        .await?;
    
    let response_text = response.text().await.map_err(|e| e.to_string())?;
    
    // Parse the response
    #[derive(Debug, Deserialize)]
    struct UserResponse {
        success: bool,
        data: Option<UserData>,
        error: Option<String>,
    }
    
    #[derive(Debug, Deserialize)]
    struct UserData {
        user: User,
    }
    
    #[derive(Debug, Deserialize)]
    struct User {
        id: String,
    }
    
    let data: UserResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    if !data.success {
        return Err(data.error.unwrap_or_else(|| "Unknown error occurred".to_string()));
    }
    
    // Extract user ID from the response
    match data.data {
        Some(user_data) => Ok(user_data.user.id),
        None => Err("No user data in response".into()),
    }
}

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
    pub success: bool,
    pub message: Option<String>,
    pub data: UserDetail,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)] // Added PartialEq for tests
struct UserDetail {
    id: String,
    username: String,
    email: Option<String>,
    role: String,
    is_active: bool,
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
    FetchCurrentUser,
    CurrentUserFetched(Result<String, String>),
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
    current_user_id: Option<String>,
}

impl Component for UserDetailComponent {
    type Message = Msg;
    type Properties = UserDetailProps;

    fn create(ctx: &Context<Self>) -> Self {
        let user_id = ctx.props().user_id.clone();
        if !cfg!(test) { // Prevent network calls during unit/integration tests
            ctx.link().send_message(Msg::FetchUserDetail);
            ctx.link().send_message(Msg::FetchCurrentUser);
        }
        
        Self {
            user_id,
            mode: ctx.props().mode.clone(),
            user_detail: None,
            error: None,
            success_message: None,
            is_loading: !cfg!(test), // In tests, assume not loading. For app, start loading.
            edited_fields: std::collections::HashMap::new(),
            current_user_id: None,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::FetchUserDetail => {
                self.is_loading = true; // Set loading state
                if !cfg!(test) {
                    let user_id = self.user_id.clone();
                    let link = ctx.link().clone();
                    spawn_local(async move {
                        let result = fetch_user_detail(&user_id).await;
                        link.send_message(Msg::UserDetailFetched(result));
                    });
                }
                true 
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
            Msg::FetchCurrentUser => {
                if !cfg!(test) {
                    let link = ctx.link().clone();
                    spawn_local(async move {
                        let result = fetch_current_user_id().await;
                        link.send_message(Msg::CurrentUserFetched(result));
                    });
                }
                false 
            }
            Msg::CurrentUserFetched(result) => {
                match result {
                    Ok(user_id) => {
                        self.current_user_id = Some(user_id);
                        
                        // If this is the current user and we're in edit mode, show an error
                        // The specific fields will be disabled, so this global error is not needed.
                        // if self.mode == "edit" && Some(&self.user_id) == self.current_user_id.as_ref() {
                        //     self.error = Some("You cannot edit your own account. This could lead to session inconsistency issues.".to_string());
                        // }
                    }
                    Err(error) => {
                        log!("Failed to fetch current user ID: {}", error);
                        // Don't set an error message for this, as it's not critical for the UI
                    }
                }
                true
            }
            Msg::UpdateField(field, value) => {
                self.edited_fields.insert(field, value);
                true
            }
            Msg::SaveUser => {
                if self.mode != "edit" { return false; }
                self.is_loading = true;
                if !cfg!(test) {
                    let user_id = self.user_id.clone();
                    let edited_fields = self.edited_fields.clone();
                    let link = ctx.link().clone();
                    spawn_local(async move {
                        let result = save_user(&user_id, &edited_fields).await;
                        link.send_message(Msg::UserSaved(result));
                    });
                }
                true
            }
            Msg::UserSaved(result) => {
                self.is_loading = false;
                match result {
                    Ok(_) => {
                        self.success_message = Some("User updated successfully".to_string());
                        self.error = None;
                        if !cfg!(test) { // Avoid re-fetching in tests after save
                           ctx.link().send_message(Msg::FetchUserDetail);
                        }
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
                let options = web_sys::CustomEventInit::new();
                options.set_detail(&JsValue::from_str("UserManagement"));
                
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
        
        // Check if this is the current user
        let is_current_user = self.current_user_id.as_ref()
            .map(|current_id| current_id == &self.user_id)
            .unwrap_or(false);
        
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
                        
                        // Warning block for self-editing removed as per requirement
                        // {
                        //     if is_current_user && is_edit_mode {
                        //         html! {
                        //             <div class="c-validation__warning--user-detail">
                        //                 <svg class="c-validation__icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        //                     <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        //                     <line x1="12" y1="9" x2="12" y2="13"></line>
                        //                     <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        //                 </svg>
                        //                 {"You cannot edit your own account. This could lead to session inconsistency issues."}
                        //             </div>
                        //         }
                        //     } else {
                        //         html! { <></> }
                        //     }
                        // }
                        
                        {
                            if self.is_loading {
                                html! {
                                    <div class="c-loader--user-detail">
                                        <div class="c-loader__spinner"></div>
                                        {"Loading user details..."}
                                    </div>
                                }
                            } else if let Some(user) = &self.user_detail {
                                // Pass is_edit_mode and is_current_user separately
                                self.render_user_form(ctx, user, is_edit_mode, is_current_user)
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
    fn render_user_form(&self, ctx: &Context<Self>, user: &UserDetail, is_edit_mode: bool, is_current_user: bool) -> Html {
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
                                id="user-id-input" // For tests
                                class="c-form__input c-form__input--user-detail"
                                value={user.id.clone()} 
                                disabled=true
                            />
                        </div>
                        
                        <div class="c-form__group">
                            <label class="c-form__label" for="username-input">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle>
                                </svg>
                                {"Username"}
                            </label>
                            <input 
                                type="text" 
                                id="username-input" // For tests
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
                                id="email-input" // For tests
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
                                id="role-select" // For tests
                                class="c-form__select c-form__select--user-detail" 
                                disabled={!is_edit_mode || (is_edit_mode && is_current_user)}
                                onchange={
                                    if is_edit_mode && !(is_edit_mode && is_current_user) { // only allow change if not disabled
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
                            <label class="c-form__label">
                                <svg class="c-form__label-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    // Using a generic check-circle icon for active status for now
                                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>
                                </svg>
                                {"Active Status"}
                            </label>
                            <select 
                                id="status-select" // For tests
                                class="c-form__select c-form__select--user-detail" 
                                disabled={!is_edit_mode || (is_edit_mode && is_current_user)}
                                onchange={
                                    if is_edit_mode && !(is_edit_mode && is_current_user) { // only allow change if not disabled
                                        ctx.link().callback(|e: Event| {
                                            let select: HtmlSelectElement = e.target_unchecked_into();
                                            Msg::UpdateField("status".to_string(), select.value())
                                        })
                                    } else {
                                        Callback::noop()
                                    }
                                }
                            >
                                <option 
                                    value="true" 
                                    selected={
                                        self.edited_fields.get("status")
                                            .cloned()
                                            .unwrap_or_else(|| user.is_active.to_string()) == "true"
                                    }
                                >
                                    {"Active"}
                                </option>
                                <option 
                                    value="false" 
                                    selected={
                                        self.edited_fields.get("status")
                                            .cloned()
                                            .unwrap_or_else(|| user.is_active.to_string()) == "false"
                                    }
                                >
                                    {"Inactive"}
                                </option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="c-form__group"> // This div was part of the original, ensuring it's still here
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
    log!("UserDetail: Sending request to {}", url);
    
    // Use send_with_retry() for proper token refresh handling
    let response = request.send_with_retry().await.map_err(|e| e.to_string())?;
    
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
    log!("UserDetail: Saving user changes for ID: {}", user_id);
    
    // First check if this is the current user - This check is removed as per requirements.
    // The backend will handle prevention of critical field changes for one's own account.
    // let current_user_result = fetch_current_user_id().await;
    // if let Ok(current_user_id) = current_user_result {
    //     if current_user_id == user_id {
    //         return Err("You cannot edit your own account. This could lead to session inconsistency issues.".to_string());
    //     }
    // }
    
    // Log each field individually to avoid HashMap serialization issues
    for (key, value) in edited_fields.iter() {
        log!("UserDetail: Edited field - {} = {}", key, value);
    }

    // Process each edited field with the appropriate endpoint
    for (field, value) in edited_fields.iter() {
        let endpoint_url = match field.as_str() {
            "username" => format!("/api/cookie/admin/users/{}/username", user_id),
            "role" => format!("/api/cookie/admin/users/{}/role", user_id),
            "status" => format!("/api/cookie/admin/users/{}/status", user_id),
            _ => continue, // Skip unknown fields
        };

        // Create a JSON object with the field value
        let mut json_data = serde_json::Map::new();
        
        // Insert the correct field name based on the endpoint
        match field.as_str() {
            "username" => { json_data.insert("username".to_string(), serde_json::Value::String(value.clone())); }
            "role" => { json_data.insert("role".to_string(), serde_json::Value::String(value.clone())); }
            "status" => { json_data.insert("is_active".to_string(), serde_json::Value::Bool(value == "true")); }
            _ => continue,
        }
        
        log!("UserDetail: Sending request to update {} to {}", field, &endpoint_url);
        
        let request = RequestInterceptor::put(&endpoint_url)
            .json(&serde_json::Value::Object(json_data))
            .map_err(|e| format!("Failed to create request for {}: {}", field, e))?;
        
        // Use send_with_retry() for proper token refresh handling
        let response = request.send_with_retry().await.map_err(|e| e.to_string())?;
        
        if !response.ok() {
            let status = response.status();
            return Err(format!("Failed to update {}: {}", field, status));
        }
        
        let response_text = response.text().await
            .map_err(|e| format!("Failed to get response text for {}: {}", field, e))?;
        
        log!("UserDetail: Update response for {}: {}", field, &response_text);
        
        // Handle different response types based on the field
        if field == "username" || field == "role" {
            // For username and role updates, expect a UserDetail response
            let api_response: ApiResponse<UserDetail> = serde_json::from_str(&response_text)
                .map_err(|e| format!("Failed to parse response for {}: {}", field, e))?;
                
            if !api_response.success {
                return Err(api_response.error.unwrap_or_else(|| format!("Unknown error occurred updating {}", field)));
            }
        } else {
            // For other fields, expect a unit response
            let api_response: ApiResponse<()> = serde_json::from_str(&response_text)
                .map_err(|e| format!("Failed to parse response for {}: {}", field, e))?;
                
            if !api_response.success {
                return Err(api_response.error.unwrap_or_else(|| format!("Unknown error occurred updating {}", field)));
            }
        }
    }
    
    Ok(())
}

// Function to fetch the current user's ID
async fn fetch_current_user_id() -> Result<String, String> {
    // Use the RequestInterceptor to handle token refresh automatically
    let response = RequestInterceptor::get("/api/cookie/users/me")
        .send_with_retry()
        .await
        .map_err(|e| e.to_string())?;
    
    let response_text = response.text().await.map_err(|e| e.to_string())?;
    
    // Parse the response
    let data: UserDetailResponse = serde_json::from_str(&response_text)
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
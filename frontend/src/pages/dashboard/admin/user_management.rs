use yew::prelude::*;
use crate::pages::dashboard::User;

#[derive(Properties, PartialEq)]
pub struct UserManagementProps {
    pub user: Option<User>,
}

pub struct UserManagement;

impl Component for UserManagement {
    type Message = ();
    type Properties = UserManagementProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"User Management"}</h2>
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
                                    if let Some(user_info) = &ctx.props().user {
                                        // Show current user as example
                                        html! {
                                            <tr>
                                                <td>{&user_info.username}</td>
                                                <td>{user_info.email.as_deref().unwrap_or("Not provided")}</td>
                                                <td>
                                                    <span class={classes!("c-badge", if user_info.is_email_verified { "c-badge--success" } else { "c-badge--warning" })}>
                                                        {if user_info.is_email_verified { "Verified" } else { "Unverified" }}
                                                    </span>
                                                </td>
                                                <td>
                                                    <span class={classes!("c-badge", if user_info.is_admin() { "c-badge--primary" } else { "c-badge--secondary" })}>
                                                        {&user_info.role}
                                                    </span>
                                                </td>
                                                <td>{&user_info.created_at}</td>
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

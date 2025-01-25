use yew::prelude::*;
use super::User;

#[derive(Properties, PartialEq)]
pub struct ProfileProps {
    pub user: Option<User>,
}

pub struct Profile;

impl Component for Profile {
    type Message = ();
    type Properties = ProfileProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let content = if let Some(user) = &ctx.props().user {
            html! {
                <div class="l-grid l-grid--stats">
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                            <circle cx="12" cy="7" r="4"></circle>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Username"}</span>
                            <span class="c-card__value">{&user.username}</span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                            <polyline points="22,6 12,13 2,6"></polyline>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Email"}</span>
                            <span class="c-card__value">{user.email.as_deref().unwrap_or("Not provided")}</span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                            <polyline points="22 4 12 14.01 9 11.01"></polyline>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Email Status"}</span>
                            <span class={classes!("c-card__value", if user.is_email_verified { "is-verified" } else { "is-unverified" })}>
                                {if user.is_email_verified { "Verified" } else { "Not Verified" }}
                            </span>
                        </div>
                    </div>
                    <div class="c-card c-card--stat">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="16" y1="2" x2="16" y2="6"></line>
                            <line x1="8" y1="2" x2="8" y2="6"></line>
                            <line x1="3" y1="10" x2="21" y2="10"></line>
                        </svg>
                        <div class="stat-content">
                            <span class="c-card__label">{"Account Created"}</span>
                            <span class="c-card__value">{&user.created_at}</span>
                        </div>
                    </div>
                </div>
            }
        } else {
            html! {
                <div class="c-loader c-loader--circular">{"Loading profile information..."}</div>
            }
        };

        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Profile Information"}</h2>
                    {content}
                </div>
            </div>
        }
    }
}

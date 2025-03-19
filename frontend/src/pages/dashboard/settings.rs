use yew::prelude::*;

mod tabs;

#[derive(Clone, PartialEq)]
pub enum SettingsTab {
    Account,
    Security,
    Notifications,
    Appearance,
    Privacy,
}

pub struct Settings {
    active_tab: SettingsTab,
}

pub enum Msg {
    SwitchTab(SettingsTab),
}

impl Component for Settings {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            active_tab: SettingsTab::Account,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::SwitchTab(tab) => {
                self.active_tab = tab;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let link = ctx.link();
        
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Settings"}</h2>
                    
                    <div class="c-tabs">
                        <div class="c-tabs__nav">
                            <button 
                                class={classes!("c-tabs__tab", (self.active_tab == SettingsTab::Account).then_some("c-tabs__tab--active"))}
                                onclick={link.callback(|_| Msg::SwitchTab(SettingsTab::Account))}
                            >
                                {"Account"}
                            </button>
                            <button 
                                class={classes!("c-tabs__tab", (self.active_tab == SettingsTab::Security).then_some("c-tabs__tab--active"))}
                                onclick={link.callback(|_| Msg::SwitchTab(SettingsTab::Security))}
                            >
                                {"Security"}
                            </button>
                            <button 
                                class={classes!("c-tabs__tab", (self.active_tab == SettingsTab::Notifications).then_some("c-tabs__tab--active"))}
                                onclick={link.callback(|_| Msg::SwitchTab(SettingsTab::Notifications))}
                            >
                                {"Notifications"}
                            </button>
                            <button 
                                class={classes!("c-tabs__tab", (self.active_tab == SettingsTab::Appearance).then_some("c-tabs__tab--active"))}
                                onclick={link.callback(|_| Msg::SwitchTab(SettingsTab::Appearance))}
                            >
                                {"Appearance"}
                            </button>
                            <button 
                                class={classes!("c-tabs__tab", (self.active_tab == SettingsTab::Privacy).then_some("c-tabs__tab--active"))}
                                onclick={link.callback(|_| Msg::SwitchTab(SettingsTab::Privacy))}
                            >
                                {"Privacy"}
                            </button>
                        </div>
                        
                        <div class="c-tabs__content">
                            {self.render_active_tab()}
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}

impl Settings {
    fn render_active_tab(&self) -> Html {
        match self.active_tab {
            SettingsTab::Account => html! { <tabs::AccountSettings /> },
            SettingsTab::Security => html! { <tabs::SecuritySettings /> },
            SettingsTab::Notifications => html! { <tabs::NotificationSettings /> },
            SettingsTab::Appearance => html! { <tabs::AppearanceSettings /> },
            SettingsTab::Privacy => html! { <tabs::PrivacySettings /> },
        }
    }
}

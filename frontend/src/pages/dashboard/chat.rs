 use yew::prelude::*;

pub struct Chat;

impl Component for Chat {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        false
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class="c-card c-card--dashboard">
                <h2 class="c-card__title">{"Chat"}</h2>

                // Chat interface
                <div class="chat-container">
                    // Sidebar for chat history
                    <div class="chat-sidebar">
                        <div class="chat-history-item active">
                            <h4>{"Conversation 1"}</h4>
                            <p class="chat-history-preview">{"Latest message preview..."}</p>
                        </div>
                        <div class="chat-history-item">
                            <h4>{"Conversation 2"}</h4>
                            <p class="chat-history-preview">{"Another conversation preview..."}</p>
                        </div>
                        <div class="chat-history-item">
                            <h4>{"Conversation 3"}</h4>
                            <p class="chat-history-preview">{"More message previews..."}</p>
                        </div>
                    </div>

                    // Main chat interface
                    <div class="chat-main">
                        // Messages area
                        <div class="chat-messages">
                            <div class="message message--user">
                                <p>{"Hi, how can I assist you today?"}</p>
                                <div class="message__timestamp">{"09:00 AM"}</div>
                            </div>
                            <div class="message message--llm">
                                <p>{"I'm looking for information on your services."}</p>
                                <div class="message__timestamp">{"09:01 AM"}</div>
                            </div>
                        </div>

                        // Input area
                        <div class="chat-input">
                            <form class="chat-input__form">
                                <textarea 
                                    class="chat-input__textarea"
                                    placeholder="Type your message..."
                                ></textarea>
                                <button type="submit" class="chat-input__button">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <line x1="22" y1="2" x2="11" y2="13"></line>
                                        <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                                    </svg>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
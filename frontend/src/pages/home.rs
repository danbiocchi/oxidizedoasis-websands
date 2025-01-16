use yew::prelude::*;
use yew::use_effect_with;
use gloo_timers::callback::Interval;

#[function_component(Home)]
pub fn home() -> Html {
    let drone_position = use_state(|| 0);
    
    {
        let drone_position = drone_position.clone();
        use_effect_with((), move |_| {
            let interval = Interval::new(50, move || {
                drone_position.set((*drone_position + 1) % 360);
            });
            || drop(interval)
        });
    }

    html! {
        <main>
            <div class="hero-section">
                <section class="welcome-container">
                    <div class="drone-animation">
                        <div class="drone" style={format!("transform: translate(-50%, -50%) rotate({}deg)", *drone_position)}>
                            <i class="fas fa-helicopter"></i>
                        </div>
                    </div>
                    <h1 class="title-animation">{"Cipher Horizon"}</h1>
                    <p class="fade-in">{"Pioneering the Future of Autonomous Flight"}</p>
                </section>
            </div>

            <div class="content-sections">
                <section class="features-section">
                    <div class="section-content">
                        <h2>{"Next-Generation Drone Technology"}</h2>
                        <div class="features-grid">
                            <div class="feature-card">
                                <i class="fas fa-shield"></i>
                                <h3>{"Military-Grade Security"}</h3>
                                <p>{"Advanced encryption and secure communication protocols for mission-critical operations"}</p>
                            </div>
                            <div class="feature-card">
                                <i class="fas fa-microchip"></i>
                                <h3>{"Autonomous Systems"}</h3>
                                <p>{"AI-powered flight control and advanced obstacle avoidance technology"}</p>
                            </div>
                            <div class="feature-card">
                                <i class="fas fa-network-wired"></i>
                                <h3>{"Fleet Management"}</h3>
                                <p>{"Centralized control system for coordinating multiple drones in real-time"}</p>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="highlights-section">
                    <div class="section-content">
                        <h2>{"Why Choose Cipher Horizon"}</h2>
                        <div class="highlights-grid">
                            <div class="highlight-item">
                                <i class="fas fa-bolt"></i>
                                <h3>{"High Performance"}</h3>
                                <p>{"Ultra-low latency control systems powered by Rust"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-brain"></i>
                                <h3>{"Smart Analytics"}</h3>
                                <p>{"Real-time data processing and mission analytics"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-cloud"></i>
                                <h3>{"Cloud Integration"}</h3>
                                <p>{"Seamless cloud connectivity for global operations"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-lock"></i>
                                <h3>{"Secure Platform"}</h3>
                                <p>{"End-to-end encryption and access control"}</p>
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </main>
    }
}

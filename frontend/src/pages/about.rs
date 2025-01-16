use yew::prelude::*;

#[function_component(About)]
pub fn about() -> Html {
    html! {
        <main>
            <div class="about-container">
                <h1 class="about-title">{"About Cipher Horizon"}</h1>
                
                <div class="about-section">
                    <h2>{"Revolutionizing Drone Technology"}</h2>
                    <p>{"At Cipher Horizon, we're pioneering the future of autonomous aerial systems. Our cutting-edge platform combines advanced robotics with state-of-the-art security, powered by Rust's robust performance and safety guarantees."}</p>
                </div>

                <div class="tech-stack-section">
                    <h2>{"Core Technologies"}</h2>
                    <div class="tech-cards">
                        <div class="tech-card">
                            <i class="fas fa-shield"></i>
                            <h3>{"Military-Grade Security"}</h3>
                            <p>{"Advanced encryption protocols, secure communication channels, and real-time threat detection powered by Rust's memory safety guarantees."}</p>
                        </div>
                        <div class="tech-card">
                            <i class="fas fa-microchip"></i>
                            <h3>{"Smart Autonomy"}</h3>
                            <p>{"AI-powered flight systems, advanced obstacle avoidance, and intelligent mission planning for optimal performance."}</p>
                        </div>
                        <div class="tech-card">
                            <i class="fas fa-network-wired"></i>
                            <h3>{"Fleet Management"}</h3>
                            <p>{"Centralized control system for managing multiple drones, real-time telemetry, and automated mission coordination."}</p>
                        </div>
                    </div>
                </div>

                <div class="mission-section">
                    <h2>{"Our Vision"}</h2>
                    <p>{"We envision a future where autonomous drones revolutionize industries, from precision agriculture to urban planning. Our mission is to make this future a reality through innovative technology and unwavering commitment to safety and reliability."}</p>
                </div>

                <div class="features-section">
                    <h2>{"Advanced Capabilities"}</h2>
                    <ul class="feature-list">
                        <li><i class="fas fa-satellite"></i>{"GPS-independent navigation systems"}</li>
                        <li><i class="fas fa-bolt"></i>{"Ultra-low latency control interface"}</li>
                        <li><i class="fas fa-brain"></i>{"AI-powered decision making"}</li>
                        <li><i class="fas fa-chart-line"></i>{"Real-time analytics and reporting"}</li>
                        <li><i class="fas fa-expand-arrows-alt"></i>{"Scalable multi-drone operations"}</li>
                    </ul>
                </div>
            </div>
        </main>
    }
}

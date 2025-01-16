use yew::prelude::*;
use yew::use_effect_with;
use gloo_timers::callback::Interval;

#[function_component(Home)]
pub fn home() -> Html {
    let icon_spin = use_state(|| 0);
    
    {
        let icon_spin = icon_spin.clone();
        use_effect_with((), move |_| {
            let interval = Interval::new(50, move || {
                icon_spin.set((*icon_spin + 1) % 360);
            });
            || drop(interval)
        });
    }

    html! {
        <main>
            <div class="hero-section">
                <section class="welcome-container">
                    <div class="logo-animation">
                        <div class="logo" style={format!("transform: translate(-50%, -50%) rotate({}deg)", *icon_spin)}>
                            <i class="fas fa-code"></i>
                        </div>
                    </div>
                    <h1 class="title-animation">{"OxidizedOasis"}</h1>
                    <p class="fade-in">{"Pioneering the Future of Web Development with Rust"}</p>
                </section>
            </div>

            <div class="content-sections">
                <section class="features-section">
                    <div class="section-content">
                        <h2>{"Next-Generation Web Development"}</h2>
                        <div class="features-grid">
                            <div class="feature-card">
                                <i class="fas fa-shield"></i>
                                <h3>{"Memory Safety Guarantees"}</h3>
                                <p>{"Eliminate common vulnerabilities with Rust's ownership system and zero-cost abstractions"}</p>
                            </div>
                            <div class="feature-card">
                                <i class="fas fa-microchip"></i>
                                <h3>{"WebAssembly Ready"}</h3>
                                <p>{"Compile to WebAssembly for near-native performance in the browser"}</p>
                            </div>
                            <div class="feature-card">
                                <i class="fas fa-network-wired"></i>
                                <h3>{"Full-Stack Rust"}</h3>
                                <p>{"Share types and logic between frontend and backend for a cohesive development experience"}</p>
                            </div>
                            <div class="feature-card">
                                <i class="fas fa-user-shield"></i>
                                <h3>{"Robust Authentication"}</h3>
                                <p>{"Industry-standard JWT authentication with secure password handling and rate limiting"}</p>
                            </div>
                        </div>
                    </div>
                </section>

                <section class="highlights-section">
                    <div class="section-content">
                        <h2>{"Why Choose OxidizedOasis"}</h2>
                        <div class="highlights-grid">
                            <div class="highlight-item">
                                <i class="fas fa-bolt"></i>
                                <h3>{"Unmatched Performance"}</h3>
                                <p>{"Rust's zero-overhead abstractions deliver native-speed web applications"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-brain"></i>
                                <h3>{"Type-Safe Development"}</h3>
                                <p>{"Catch errors at compile-time with Rust's powerful type system"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-cloud"></i>
                                <h3>{"Modern Architecture"}</h3>
                                <p>{"Built on Actix-web, Yew, and SQLx for robust full-stack applications"}</p>
                            </div>
                            <div class="highlight-item">
                                <i class="fas fa-lock"></i>
                                <h3>{"Enterprise Security"}</h3>
                                <p>{"Memory-safe code with industry-standard authentication and encryption"}</p>
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </main>
    }
}

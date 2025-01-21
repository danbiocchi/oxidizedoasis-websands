use yew::prelude::*;

#[function_component(Home)]
pub fn home() -> Html {
    html! {
        <main class="p-home">
            <div class="p-home__hero">
                <div class="p-home__hero-content">
                    <div class="p-home__hero-logo">
                        <div class="p-home__hero-icon animate-spin">
                            <i class="fas fa-code"></i>
                        </div>
                    </div>
                    <h1 class="p-home__hero-title">{"OxidizedOasis"}</h1>
                    <p class="p-home__hero-subtitle">{"Pioneering the Future of Web Development with Rust"}</p>
                </div>
            </div>

            <div class="p-home__content">
                <section class="p-home__features">
                    <div class="p-home__section-header">
                        <h2 class="p-home__section-title">{"Next-Generation Web Development"}</h2>
                    </div>
                    <div class="p-home__features-grid">
                        <div class="p-home__feature-card">
                            <i class="fas fa-shield p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"Memory Safety Guarantees"}</h3>
                            <p class="p-home__feature-description">{"Eliminate common vulnerabilities with Rust's ownership system and zero-cost abstractions"}</p>
                        </div>
                        <div class="p-home__feature-card">
                            <i class="fas fa-microchip p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"WebAssembly Ready"}</h3>
                            <p class="p-home__feature-description">{"Compile to WebAssembly for near-native performance in the browser"}</p>
                        </div>
                        <div class="p-home__feature-card">
                            <i class="fas fa-network-wired p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"Full-Stack Rust"}</h3>
                            <p class="p-home__feature-description">{"Share types and logic between frontend and backend for a cohesive development experience"}</p>
                        </div>
                        <div class="p-home__feature-card">
                            <i class="fas fa-user-shield p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"Robust Authentication"}</h3>
                            <p class="p-home__feature-description">{"Industry-standard JWT authentication with secure password handling and rate limiting"}</p>
                        </div>
                        <div class="p-home__feature-card">
                            <i class="fas fa-database p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"Type-Safe Database"}</h3>
                            <p class="p-home__feature-description">{"Compile-time SQL query validation with SQLx for reliable data operations"}</p>
                        </div>
                        <div class="p-home__feature-card">
                            <i class="fas fa-sync p-home__feature-icon"></i>
                            <h3 class="p-home__feature-title">{"Async Runtime"}</h3>
                            <p class="p-home__feature-description">{"Efficient concurrent operations with Rust's async/await and Tokio runtime"}</p>
                        </div>
                    </div>
                </section>

                <section class="p-home__highlights">
                    <div class="p-home__section-header">
                        <h2 class="p-home__section-title">{"Why Choose OxidizedOasis"}</h2>
                    </div>
                    <div class="p-home__highlights-grid">
                        <div class="p-home__highlight-card">
                            <i class="fas fa-bolt p-home__highlight-icon"></i>
                            <h3 class="p-home__highlight-title">{"Unmatched Performance"}</h3>
                            <p class="p-home__highlight-description">{"Rust's zero-overhead abstractions deliver native-speed web applications"}</p>
                        </div>
                        <div class="p-home__highlight-card">
                            <i class="fas fa-brain p-home__highlight-icon"></i>
                            <h3 class="p-home__highlight-title">{"Type-Safe Development"}</h3>
                            <p class="p-home__highlight-description">{"Catch errors at compile-time with Rust's powerful type system"}</p>
                        </div>
                        <div class="p-home__highlight-card">
                            <i class="fas fa-cloud p-home__highlight-icon"></i>
                            <h3 class="p-home__highlight-title">{"Modern Architecture"}</h3>
                            <p class="p-home__highlight-description">{"Built on Actix-web, Yew, and SQLx for robust full-stack applications"}</p>
                        </div>
                        <div class="p-home__highlight-card">
                            <i class="fas fa-lock p-home__highlight-icon"></i>
                            <h3 class="p-home__highlight-title">{"Enterprise Security"}</h3>
                            <p class="p-home__highlight-description">{"Memory-safe code with industry-standard authentication and encryption"}</p>
                        </div>
                    </div>
                </section>
            </div>
        </main>
    }
}

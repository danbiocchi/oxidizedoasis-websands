use yew::prelude::*;

#[function_component(About)]
pub fn about() -> Html {
    html! {
        <main class="p-about">
            <div class="p-about__hero">
                <div class="p-about__hero-content">
                    <h1 class="p-about__hero-title">{"About OxidizedOasis"}</h1>
                    <h2 class="p-about__hero-subtitle">{"Modern Full-Stack Rust Development"}</h2>
                    <p class="p-about__hero-text">{"OxidizedOasis represents the cutting edge of web development, leveraging Rust's powerful ecosystem for both frontend and backend development. Our platform demonstrates the capabilities of Rust in building secure, performant, and maintainable web applications."}</p>
                </div>
            </div>

            <div class="p-about__content">

                <div class="p-about__values">
                    <h2 class="p-about__section-title">{"Technology Stack"}</h2>
                    <div class="p-about__values-grid">
                        <div class="p-about__value-card">
                            <i class="fas fa-server"></i>
                            <h3>{"Backend Excellence"}</h3>
                            <p>{"Built with Actix-web, delivering ultra-fast HTTP handling with async/await patterns. Features comprehensive middleware for security, rate limiting, and detailed logging. Implements JWT authentication with bcrypt password hashing for robust security."}</p>
                        </div>
                        <div class="p-about__value-card">
                            <i class="fas fa-code"></i>
                            <h3>{"Modern Frontend"}</h3>
                            <p>{"Powered by Yew and WebAssembly, delivering native-speed performance in the browser. Features component-based architecture, robust state management, and seamless type sharing with the backend for a cohesive development experience."}</p>
                        </div>
                        <div class="p-about__value-card">
                            <i class="fas fa-database"></i>
                            <h3>{"Data Management"}</h3>
                            <p>{"PostgreSQL integration through SQLx provides type-safe queries with compile-time checking. Includes automated migrations, efficient connection pooling, and leverages Rust's type system for guaranteed data integrity."}</p>
                        </div>
                        <div class="p-about__value-card">
                            <i class="fas fa-shield-alt"></i>
                            <h3>{"Security First"}</h3>
                            <p>{"Comprehensive security features including XSS protection, CORS configuration, input validation, and rate limiting. Implements secure email verification and password reset flows with time-limited tokens."}</p>
                        </div>
                        <div class="p-about__value-card">
                            <i class="fas fa-cogs"></i>
                            <h3>{"DevOps Ready"}</h3>
                            <p>{"Built with modern deployment in mind, featuring Docker containerization, automated testing pipelines, and comprehensive logging. Supports seamless CI/CD integration through GitHub Actions."}</p>
                        </div>
                        <div class="p-about__value-card">
                            <i class="fas fa-project-diagram"></i>
                            <h3>{"Scalable Architecture"}</h3>
                            <p>{"Domain-driven design principles ensure maintainable and extensible codebase. Modular structure with clear separation of concerns enables easy feature additions and modifications."}</p>
                        </div>
                    </div>
                </div>

                <div class="p-about__mission">
                    <div class="p-about__mission-content">
                        <h2 class="p-about__section-title">{"Development Philosophy"}</h2>
                        <p class="p-about__mission-text">{"OxidizedOasis-WebSands is designed to showcase the power of Rust in modern web development. We leverage Rust's zero-cost abstractions and memory safety guarantees to create applications that are inherently secure, blazingly fast, and maintainable. Our architecture demonstrates how type-safe development and robust error handling can elevate web applications to new heights of reliability and performance."}</p>
                    </div>
                </div>

                <div class="p-about__features">
                    <h2 class="p-about__section-title">{"Key Features"}</h2>
                    <div class="p-about__features-grid">
                        <div class="p-about__feature-card">
                            <i class="fas fa-shield-alt p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"Robust Security"}</h3>
                            <p class="p-about__feature-description">{"Industry-standard JWT authentication with bcrypt password hashing and secure email verification flows"}</p>
                        </div>
                        <div class="p-about__feature-card">
                            <i class="fas fa-tachometer-alt p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"High Performance"}</h3>
                            <p class="p-about__feature-description">{"WebAssembly compilation delivers near-native performance in the browser"}</p>
                        </div>
                        <div class="p-about__feature-card">
                            <i class="fas fa-database p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"Type-Safe Data"}</h3>
                            <p class="p-about__feature-description">{"Compile-time validated database operations with SQLx for guaranteed data integrity"}</p>
                        </div>
                        <div class="p-about__feature-card">
                            <i class="fas fa-lock p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"Advanced Security"}</h3>
                            <p class="p-about__feature-description">{"Comprehensive XSS protection and CORS security configuration"}</p>
                        </div>
                        <div class="p-about__feature-card">
                            <i class="fas fa-code-branch p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"Clean Architecture"}</h3>
                            <p class="p-about__feature-description">{"Domain-driven design principles ensure maintainable and extensible codebase"}</p>
                        </div>
                        <div class="p-about__feature-card">
                            <i class="fas fa-cogs p-about__feature-icon"></i>
                            <h3 class="p-about__feature-title">{"DevOps Ready"}</h3>
                            <p class="p-about__feature-description">{"Docker containerization with automated testing and comprehensive CI/CD integration"}</p>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    }
}

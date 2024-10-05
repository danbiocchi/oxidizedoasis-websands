use yew::prelude::*;

#[function_component(About)]
pub fn about() -> Html {
    html! {
        <main class="about-content">
            <h1>{ "About OxidizedOasis-WebSands" }</h1>

            <p>
                { "OxidizedOasis-WebSands is a robust, high-performance web application built with Rust, focusing on efficient user management and authentication. Our project demonstrates the power of Rust in web development, utilizing the Actix-web framework to create a secure, scalable user management system." }
            </p>

            <h2>{ "Key Features" }</h2>
            <ul>
                <li>{ "Secure user authentication system with JWT (JSON Web Tokens)" }</li>
                <li>{ "Efficient database operations with SQLx and PostgreSQL" }</li>
                <li>{ "Cross-Site Scripting (XSS) protection with input sanitization" }</li>
                <li>{ "Cross-Origin Resource Sharing (CORS) configuration for API security" }</li>
                <li>{ "Comprehensive input validation and error handling" }</li>
                <li>{ "Modern, responsive frontend with smooth animations" }</li>
            </ul>

            <h2>{ "Our Mission" }</h2>
            <p>
                { "At OxidizedOasis-WebSands, we strive to showcase the capabilities of Rust in creating high-performance, secure web services while maintaining excellent developer ergonomics. Our goal is to provide a solid foundation for building scalable web applications with strong security features." }
            </p>

            <h2>{ "Technology Stack" }</h2>
            <p>{ "Our application leverages a modern technology stack, including:" }</p>
            <ul>
                <li>{ "Rust programming language" }</li>
                <li>{ "Actix-web framework" }</li>
                <li>{ "PostgreSQL database" }</li>
                <li>{ "SQLx for database operations" }</li>
                <li>{ "JSON Web Tokens for authentication" }</li>
                <li>{ "Docker for containerization" }</li>
            </ul>

            <p>
                { "Explore OxidizedOasis-WebSands and experience the power of Rust in web development!" }
            </p>
        </main>
    }
}
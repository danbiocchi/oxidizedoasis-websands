# OxidizedOasis-WebSands

OxidizedOasis-WebSands is a robust, high-performance web application built with Rust, focusing on efficient user management and authentication. This project demonstrates the power of Rust in web development, utilizing the Actix-web framework to create a secure, scalable user management system.

<p align="center">
  <img src="static/images/signup-page-screenshot.png" alt="Login Page Screenshot" width="600">
</p>

## 🌟 About This Project

OxidizedOasis-WebSands is designed to provide a solid foundation for building scalable web applications with strong security features. Our goal is to showcase the capabilities of Rust in creating high-performance, secure web services while maintaining excellent developer ergonomics.

## 📚 Documentation

Comprehensive documentation for OxidizedOasis-WebSands is available to help developers, administrators, and users understand and work with the system effectively:

- [Software Development Document](docs/Software_Development_Document.md): Detailed technical specifications, architecture overview, and development guidelines.
- [Security Audit Report](docs/Security_Audit.md): In-depth analysis of the project's security measures and recommendations for improvement.
- [Security Backlog](docs/Security_Backlog.md): Ongoing security tasks and improvements planned for the project.

These documents provide valuable insights into the project's structure, security considerations, and future development plans. We encourage all contributors and users to review these resources for a deeper understanding of OxidizedOasis-WebSands.

## ✨ Key Features

- 🔒 Robust user authentication system with JWT (JSON Web Tokens)
- ✉️ Secure user registration with email verification
- 🔐 Password hashing using bcrypt for enhanced security
- 🚀 High-performance database operations with SQLx and PostgreSQL
- 🛡️ Cross-Site Scripting (XSS) protection with input sanitization
- 🌐 Cross-Origin Resource Sharing (CORS) configuration for API security
- 🔍 Comprehensive input validation and error handling
- 📊 Efficient CRUD operations for user management
- 🎨 Modern, responsive frontend with smooth animations
- 📱 Mobile-friendly design for seamless user experience across devices
- 🔧 Easily extensible architecture for adding new features

## 🛠️ Technology Stack

- **Backend**:
    - [Rust](https://www.rust-lang.org/) - A language empowering everyone to build reliable and efficient software
    - [Actix-web](https://actix.rs/) - A powerful, pragmatic, and extremely fast web framework for Rust
    - [SQLx](https://github.com/launchbadge/sqlx) - The Rust SQL Toolkit
    - [jsonwebtoken](https://github.com/Keats/jsonwebtoken) - JWT implementation in Rust
    - [bcrypt](https://docs.rs/bcrypt/latest/bcrypt/) - Easily hash and verify passwords using bcrypt

- **Database**:
    - [PostgreSQL](https://www.postgresql.org/) - The World's Most Advanced Open Source Relational Database

- **Frontend**:
    - HTML5, CSS3, and JavaScript
    - Custom CSS with modern animations for an engaging user interface

- **Development & Deployment**:
    - [Docker](https://www.docker.com/) - For containerization and easy deployment
    - [GitHub Actions](https://github.com/features/actions) - For CI/CD pipelines

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [PostgreSQL](https://www.postgresql.org/download/) (version 13 or later)
- [Docker](https://docs.docker.com/get-docker/) (optional, for containerized deployment)

### Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/oxidizedoasis-websands.git
   cd oxidizedoasis-websands
   ```

2. Set up the database:
   ```sh
   psql -c "CREATE DATABASE oxidizedoasis"
   ```

3. Set up environment variables:
   Create a `.env` file in the project root with the following content:
   ```
   DATABASE_URL=postgres://username:password@localhost/oxidizedoasis
   JWT_SECRET=your_jwt_secret_key
   SMTP_USERNAME=your_smtp_username
   SMTP_PASSWORD=your_smtp_password
   SMTP_SERVER=your_smtp_server
   FROM_EMAIL=noreply@yourdomain.com
   RUST_LOG=debug
   ```
   Replace the placeholders with your actual database and SMTP credentials.

4. Run database migrations:
   ```sh
   cargo install sqlx-cli
   sqlx migrate run
   ```

5. Build and run the project:
   ```sh
   cargo run
   ```

6. Visit `http://localhost:8080` in your browser to access the application.

## 🔧 Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL database connection string
- `JWT_SECRET`: Secret key for JWT token generation and validation
- `SMTP_USERNAME`: Username for the SMTP server (for email verification)
- `SMTP_PASSWORD`: Password for the SMTP server
- `SMTP_SERVER`: SMTP server address
- `FROM_EMAIL`: Email address used as the sender for verification emails
- `RUST_LOG`: Logging level (e.g., debug, info, warn, error)

### CORS Configuration

CORS is configured in `src/main.rs`. Modify the CORS settings to match your deployment environment:

```rust
let cors = Cors::default()
    .allowed_origin("http://localhost:8080")
    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE])
    .max_age(3600);
```

## 📚 Usage

### User Registration

To register a new user, send a POST request to `/users/register` with the following JSON payload:

```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

### User Login

To log in, send a POST request to `/users/login` with the following JSON payload:

```json
{
  "username": "newuser",
  "password": "SecurePassword123!"
}
```

A successful login will return a JWT token, which should be included in the `Authorization` header for subsequent requests.

### Protected Routes

To access protected routes, include the JWT token in the `Authorization` header:

```
Authorization: Bearer <your_jwt_token>
```

## 🧪 Testing

OxidizedOasis-WebSands uses a comprehensive test suite to ensure reliability and correctness. To run the tests:

```sh
cargo test
```

For more verbose output:

```sh
cargo test -- --nocapture
```

## 🚢 Deployment

### Docker Deployment

1. Build the Docker image:
   ```sh
   docker build -t oxidizedoasis-websands .
   ```

2. Run the container:
   ```sh
   docker run -p 8080:8080 --env-file .env oxidizedoasis-websands
   ```

### Manual Deployment

1. Build the release version:
   ```sh
   cargo build --release
   ```

2. Run the binary:
   ```sh
   ./target/release/oxidizedoasis-websands
   ```

Remember to set up your environment variables and database before deploying.

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and adhere to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## 📜 License

Distributed under the MIT License. See `LICENSE` file for more information.

## 📬 Contact

Daniel Biocchi - daniel@biocchi.ca
Fabio Campioni

Project Link: [https://github.com/yourusername/oxidizedoasis-websands](https://github.com/yourusername/oxidizedoasis-websands)

## 🙏 Acknowledgements

- [Rust](https://www.rust-lang.org/)
- [Actix-web](https://actix.rs/)
- [SQLx](https://github.com/launchbadge/sqlx)
- [PostgreSQL](https://www.postgresql.org/)
- [JSON Web Tokens](https://jwt.io/)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)

## 📊 Project Status

![Build Status](https://img.shields.io/github/workflow/status/yourusername/oxidizedoasis-websands/Rust)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Rust Version](https://img.shields.io/badge/Rust-1.68%2B-orange.svg)

---

<p align="center">
  Made with ❤️ by the OxidizedOasis-WebSands Team
</p>


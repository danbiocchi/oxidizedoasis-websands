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
- [User Guide](docs/User_Guide.md): Guide for end-users on how to use the application.
- [Project Structure](docs/Project_Structure.md): Overview of the project's directory structure and file organization.
- [Logging Plan](docs/Logging_Plan.md): Detailed plan for implementing comprehensive logging in the project.
- [Testing Backlog](docs/Testing_Backlog.md): List of tests to be implemented as part of the test-driven development approach.

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
- 🔄 Database migrations for easy schema management and updates
- 🧪 Test-driven development approach for improved code quality and reliability

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
   git clone https://github.com/danbiocchi/oxidizedoasis-websands.git
   cd oxidizedoasis-websands
   ```

2. Set up the environment variables:
   Create two files in the project root: `.env` for development and `.env.test` for testing.

   `.env` file content:
   ```
   ENVIRONMENT=development
   DEVELOPMENT_URL=http://localhost:8080
   SERVER_HOST=127.0.0.1
   SERVER_PORT=8080
   
   DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}
   SU_DATABASE_URL=postgres://${SU_DB_USER}:${SU_DB_PASSWORD}@${DB_HOST}/${DB_NAME}
   RUN_MIGRATIONS=true
   
   JWT_SECRET=your_jwt_secret_key
   
   SMTP_USERNAME=your_smtp_username
   SMTP_PASSWORD=your_smtp_password
   SMTP_SERVER=your_smtp_server
   FROM_EMAIL=noreply@yourdomain.com
   
   RUST_LOG=debug
   ```

   `.env.test` file content:
   ```
   ENVIRONMENT=development
   DEVELOPMENT_URL=http://localhost:8080
   RUN_MIGRATIONS=true
   TEST_SERVER_HOST=127.0.0.1
   TEST_SERVER_PORT=8080
   
   
   TEST_DATABASE_URL=postgres://${TEST_DB_USER}:${TEST_DB_PASSWORD}@${TEST_DB_HOST}/${TEST_DB_NAME}
   TEST_SU_DATABASE_URL=postgres://${TEST_DB_SUPERUSER}:${TEST_DB_SUPERUSER_PASSWORD}@${TEST_DB_HOST}/${TEST_DB_NAME}
   
   TEST_JWT_SECRET=your_test_jwt_secret_key
   
   TEST_SMTP_USERNAME=your_test_smtp_username
   TEST_SMTP_PASSWORD=your_test_smtp_password
   TEST_SMTP_SERVER=your_test_smtp_server
   TEST_FROM_EMAIL=test_noreply@yourdomain.com

   TEST_DB_NAME=test_oxidizedoasis
   TEST_DB_USER=testuser
   
   RUST_LOG=debug
   ```

   Replace the placeholders with your actual database, SMTP, and other credentials.

3. Build and run the project:
   ```sh
   cargo run
   ```

4. The application will automatically create the database if it doesn't exist, run all necessary migrations, and start the server.

5. Visit `http://localhost:8080` in your browser to access the application.

## 🔧 Configuration

Refer to the [Software Development Document](docs/Software_Development_Document.md) for detailed configuration instructions and environment variable descriptions.

## 📚 Usage

Refer to the [User Guide](docs/User_Guide.md) for detailed information on how to use the application.

## 🧪 Testing

We follow a test-driven development (TDD) approach. To run the tests:

```sh
cargo test
```

For more information on our testing strategy and backlog, refer to the [Testing Backlog](docs/Testing_Backlog.md).

## 🚢 Deployment

Refer to the [Software Development Document](docs/Software_Development_Document.md) for detailed deployment instructions.

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and adhere to the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).

## 📬 Contact

Daniel Biocchi

Project Link: [https://github.com/danbiocchi/oxidizedoasis-websands](https://github.com/danbiocchi/oxidizedoasis-websands)

## 🙏 Acknowledgements

- [Rust](https://www.rust-lang.org/)
- [Actix-web](https://actix.rs/)
- [SQLx](https://github.com/launchbadge/sqlx)
- [PostgreSQL](https://www.postgresql.org/)
- [JSON Web Tokens](https://jwt.io/)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- Diablo 2

---

<p align="center">
  Made with ❤️ by the OxidizedOasis-WebSands Team
</p>
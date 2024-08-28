# OxidizedOasis-WebSands

OxidizedOasis-WebSands is a robust web application built with Rust, focusing on efficient user management and authentication.

<p align="center">
  <img src="static/images/signup-page-screenshot.png" alt="Login Page Screenshot" width="600">
</p>

## 🌟 About This Project

This project demonstrates the power of Rust in web development, utilizing the Actix-web framework to create a high-performance, secure user management system. Our goal is to provide a solid foundation for building scalable web applications with strong security features.

## ✨ Features

- 🔒 Secure user authentication system
- ✉️ User registration with email verification
- 🔄 CRUD operations for user management
- 🚀 Efficient database connections using SQLx with PostgreSQL
- 📱 Responsive and attractive frontend for seamless user interaction
- 🔑 JWT-based authentication for secure sessions
- 🎨 Modern, animated UI with smooth transitions

## 🛠️ Tech Stack

- **Backend**: Rust, Actix-web
- **Database**: PostgreSQL
- **ORM**: SQLx
- **Frontend**: HTML, CSS, JavaScript
- **Authentication**: JWT (JSON Web Tokens)
- **Email**: Lettre for sending verification emails
- **Styling**: Custom CSS with animations

## 🚀 Getting Started

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/oxidizedoasis-websands.git
   ```

2. Navigate to the project directory:
   ```sh
   cd oxidizedoasis-websands
   ```

3. Set up the database and environment variables (see Configuration section)

4. Build and run the project:
   ```sh
   cargo run
   ```

5. Visit http://localhost:8080 in your browser to access the application

## ⚙️ Configuration

1. Create a `.env` file in the project root with the following variables:
   ```sh
   DATABASE_URL=postgres://username:password@localhost/database_name
   JWT_SECRET=your_jwt_secret_key
   SMTP_USERNAME=your_smtp_username
   SMTP_PASSWORD=your_smtp_password
   SMTP_SERVER=your_smtp_server
   FROM_EMAIL=noreply@yourdomain.com
   RUST_LOG=debug
   ```

2. Ensure you have PostgreSQL installed and running

3. Create the database and run migrations:
   ```sh
   sqlx database create
   sqlx migrate run
   ```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contributors

- Daniel Biocchi
- Fabio Campioni

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎉 Recent Updates

- Implemented email verification for new account registrations
- Enhanced the UI with a modern, animated design
- Improved error handling and user feedback
- Implemented proper CORS configuration
- Added comprehensive logging for better debugging
- Restructured the project for better organization and scalability

## 🔮 Future Enhancements

- Add password reset functionality
- Develop a comprehensive test suite
- Enhance frontend with a modern JavaScript framework
- Implement user profile management
- Add support for social media login
- Implement rate limiting and additional security measures

We're committed to continually improving OxidizedOasis-WebSands and welcome feedback and contributions from the community.

<p align="center">
  Made with ❤️ by the OxidizedOasis-WebSands Team
</p>
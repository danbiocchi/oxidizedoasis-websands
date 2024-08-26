# OxidizedOasis-WebSands

OxidizedOasis-WebSands is a robust web application built with Rust, focusing on efficient user management and authentication.

## About This Project

This project demonstrates the power of Rust in web development, utilizing the Actix-web framework to create a high-performance, secure user management system. Our goal is to provide a solid foundation for building scalable web applications with strong security features.

## Features

- Secure user authentication system
- CRUD operations for user management
- Efficient database connections using SQLx with PostgreSQL
- Responsive frontend for seamless user interaction

## Tech Stack

- Backend: Rust, Actix-web
- Database: PostgreSQL
- ORM: SQLx
- Frontend: HTML, JavaScript
- Authentication: JWT (JSON Web Tokens)

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/danbiocchi/oxidizedoasis-websands.git
   ```
2. Navigate to the project directory:
   ```
   cd oxidizedoasis-websands
   ```
3. Set up the database and environment variables (see Configuration section)
4. Build and run the project:
   ```
   cargo run
   ```
5. Visit `http://localhost:8080` in your browser to access the application

## Configuration

1. Create a `.env` file in the project root with the following variables:
   ```
   DATABASE_URL=postgres://username:password@localhost/database_name
   JWT_SECRET=your_jwt_secret_key
   ```
2. Ensure you have PostgreSQL installed and running
3. Create the database and run migrations (instructions to be added)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Contributors

- Daniel Biocchi 
- Fabio Campioni 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Future Enhancements

- Implement email verification for new accounts
- Add password reset functionality
- Develop comprehensive test suite
- Enhance frontend with a modern JavaScript framework

We're committed to continually improving OxidizedOasis-WebSands and welcome feedback and contributions from the community.
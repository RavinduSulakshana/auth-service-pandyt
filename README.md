# Go Authentication Service

This is a simple and secure authentication service built with Go. It handles user sign-up, login, and token management, and provides protected routes using JSON Web Tokens (JWT). The service uses a modular architecture and an SQLite database for data persistence.

---

### Architecture Overview

The application is designed with a clear separation of concerns:

* **`main.go`**: The application's entry point, responsible for loading configuration, initializing the database, setting up the JWT manager, and registering HTTP routes.
* **`handlers/`**: Contains the HTTP request handlers.
    * `auth.go`: Manages all user-related endpoints like sign-up, login, and profile access.
    * `admin.go`: Handles the admin-only `health` endpoint.
* **`auth/`**: Manages the authentication logic, including JWT generation, validation, and refresh token handling.
* **`database/`**: Provides the interface for all database operations, connecting to an SQLite database.
* **`models/`**: Defines the data structures used throughout the application, such as `User` and `TokenResponse`.
* **`utils/`**: Contains various helper functions, including environment variable loading and writing JSON responses.

The service uses **bcrypt** for securely hashing user passwords and **JWT** for creating secure, short-lived access tokens. Refresh tokens are hashed and stored in the database to enable secure token rotation.

---

### Setup and Running

#### Prerequisites

* Go (version 1.24.4 or higher)

#### Environment Variables

The application's configuration is managed through environment variables. Create a `.env` file in the project's root directory with the following variables:

```ini
PORT=8080
DB_PATH=./auth.db
JWT_SECRET=secret_jwt
JWT_EXPIRY_HOURS=24
ADMIN_KEY=admin_key

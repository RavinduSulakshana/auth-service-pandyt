# Go Authentication Service

This is a simple and secure authentication service built with Go. It handles user sign-up, login, and token management, and provides protected routes using JSON Web Tokens (JWT). The service uses a modular architecture and an SQLite database for data persistence.

-----

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

-----

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
```

  * `PORT`: The port on which the server will listen.
  * `DB_PATH`: The path to the SQLite database file.
  * `JWT_SECRET`: The secret key for signing JWTs.
  * `JWT_EXPIRY_HOURS`: The expiration time for JWT access tokens.
  * `ADMIN_KEY`: The key required to access admin-only endpoints.

#### Running the Application

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/RavinduSulakshana/auth-service-pandyt.git
    cd auth-service-pandyt
    ```
2.  **Install dependencies**:
    ```bash
    go mod tidy
    ```
3.  **Run the service**:
    ```bash
    go run main.go
    ```
    The server will start and be accessible at `http://localhost:8080`.

-----

### API Endpoints and cURL Examples

All JSON requests must include the `Content-Type: application/json` header.

#### Public Routes

1.  **Sign Up**

      * `POST /auth/signup`
      * **Description**: Registers a new user. The password must be at least 8 characters long and contain at least one letter and one digit.
      * **cURL Example**:
        ```bash
        curl -X POST http://localhost:8080/auth/signup \
          -H 'Content-Type: application/json' \
          -d '{"email":"testuser@example.com","password":"Password123","firstname":"Test","lastname":"User"}'
        ```

2.  **Login**

      * `POST /auth/login`
      * **Description**: Authenticates a user and issues an access token and a refresh token.
      * **cURL Example**:
        ```bash
        curl -X POST http://localhost:8080/auth/login \
          -H 'Content-Type: application/json' \
          -d '{"email":"testuser@example.com","password":"Password123"}'
        ```

3.  **Refresh Token**

      * `POST /auth/refresh`
      * **Description**: Exchanges a valid refresh token for new access and refresh tokens.
      * **cURL Example**:
        ```bash
        curl -X POST http://localhost:8080/auth/refresh \
          -H 'Content-Type: application/json' \
          -d '{"refresh_token":"your_refresh_token_here"}'
        ```

#### Protected Routes (requires `Authorization: Bearer <access_token>`)

1.  **User Profile**

      * `GET /auth/profile`
      * **Description**: Retrieves the profile information for the authenticated user.
      * **cURL Example**:
        ```bash
        curl -X GET http://localhost:8080/auth/profile \
          -H 'Authorization: Bearer <your_access_token>'
        ```

2.  **Logout**

      * `POST /auth/logout`
      * **Description**: Invalidates all active refresh tokens for the current user.
      * **cURL Example**:
        ```bash
        curl -X POST http://localhost:8080/auth/logout \
          -H 'Authorization: Bearer <your_access_token>'
        ```

#### Admin Route (requires `X-Admin-Key`)

1.  **Health Check**
      * `GET /admin/health`
      * **Description**: A simple health check endpoint accessible only to administrators.
      * **cURL Example**:
        ```bash
        curl -X GET http://localhost:8080/admin/health \
          -H 'X-Admin-Key: admin_key'
        ```

-----

### Tests

To run the project's tests, use the following command:

```bash
go test ./...
```

The tests use an in-memory database to ensure they are fast, isolated, and do not modify the main `auth.db` file.

-----

###  Docker

To build and run the application using  Dockerfile , use the provided Dockerfile.

1.  **Build the image**:
    ```bash
    docker build -t auth-service .
    ```
2.  **Run the container**:
    ```bash
    docker run -d -p 8080:8080 --name auth-app auth-service
    ```
    This will start the service in the background, accessible at `http://localhost:8080`.

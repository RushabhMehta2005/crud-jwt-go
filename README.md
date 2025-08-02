# Go JWT + CRUD Backend

## Learning Go

The purpose of this repository is to host my first backend written in Go. It is designed to be a clean, scalable, and performant template for building applications that require JWT (JSON Web Token) authentication and standard CRUD (Create, Read, Update, Delete) functionality.

This project goes beyond a basic implementation and incorporates modern Go application architecture and best practices.

---

## Features

* **JWT Authentication**: Secure, cookie-based authentication for user management.
    * User Registration (`/auth/register`)
    * User Login (`/auth/login`)
    * User Logout (`/auth/logout`)
    * Password Management (`/api/user/password`)
* **CRUD Operations for Items**: Authenticated users can manage their own items.
    * Create, Read, Update, and Delete items.
    * All item operations are scoped to the authenticated user.
* **Structured Configuration**: Centralized and environment-aware configuration management.
* **Database Migrations**: Simple, script-based database schema management with GORM.

---

## Architectural Highlights & Best Practices

This project was built with scalability, performance, and maintainability in mind. The following architectural patterns and optimizations have been implemented:

### 1. Dependency Injection (DI)
* **Central Handler**: The application avoids global variables (like a global database connection). Instead, it uses a central `Handler` struct that holds all application dependencies (database connection, cache, configuration, etc.).
* **Testability**: This DI pattern makes the application highly testable, as dependencies can be easily mocked in unit tests.

### 2. Scalability and Performance
* **CPU-Intensive Task Offloading**: Password hashing with `bcrypt` is computationally expensive. To prevent this from blocking the server under load, a **worker pool** is used. Hashing jobs are sent to a dedicated set of background goroutines, keeping the main request handlers free and responsive.
* **Database Caching**: The authentication middleware (`RequireAuth`) implements an in-memory caching layer (`go-cache`) for user data. This significantly reduces redundant database lookups for authenticated requests, decreasing database load and improving API latency.
* **Efficient Database Queries**: For `UPDATE` operations, the `RETURNING` clause is used via GORM's `Clauses(clause.Returning{})`. This allows updating a record and retrieving the new data in a single database round-trip, halving the database calls for that operation.

### 3. Robust Application & Server Design
* **Graceful Shutdown & Timeouts**: The HTTP server is configured with explicit `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` values. This makes the server more resilient to slow clients and potential denial-of-service attacks like Slowloris.
* **Structured Logging**: The application uses Go's standard `log` package for clear, structured startup and error logging.
* **Configuration Management**: Application configuration (like the JWT secret and database credentials) is loaded from a `.env` file at startup, keeping secrets out of the codebase.

### 4. Go & REST API Idioms
* **RESTful Routing**: API endpoints follow REST conventions, using plural nouns for collections (e.g., `/api/items`) and proper HTTP verbs (`GET`, `POST`, `PATCH`, `DELETE`).
* **GORM Best Practices**:
    * Models embed `gorm.Model` to reduce boilerplate.
    * Foreign key constraints (`OnDelete:CASCADE`) are used to ensure data integrity.
    * Indexes are placed on foreign keys (`UserID`) for faster queries.
    * Monetary values are stored as integers to avoid floating-point precision issues.
* **Standardized Error Responses**: A helper function (`jsonError`) is used to ensure all error responses sent to the client have a consistent JSON structure.

---

## API Endpoints

### Authentication (`/auth`)
* `POST /auth/register`: Create a new user.
* `POST /auth/login`: Log in and receive an auth cookie.
* `POST /auth/logout`: Log out and clear the auth cookie.

### User (`/api/user`)
*Requires Authentication*
* `GET /api/user/profile`: Get the current user's profile information.
* `PATCH /api/user/password`: Change the current user's password.

### Items (`/api/items`)
*Requires Authentication*
* `POST /api/items`: Create a new item.
* `GET /api/items`: List all items owned by the user.
* `GET /api/items/:id`: Get a single item by its ID.
* `PATCH /api/items/:id`: Update an item's details.
* `DELETE /api/items/:id`: Delete an item.

---

## Setup & Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/RushabhMehta2005/crud-jwt-go
    cd crud-jwt
    ```

2.  **Create a `.env` file** in the root directory and add your configuration:
    ```env
    # Server Configuration
    PORT=3000

    # JWT Secret Key (use a long, random string)
    SECRET_KEY="your_super_secret_key_here"

    # Database Credentials (PostgreSQL)
    DB_CREDENTIALS="your_db_connection_string"
    ```

3.  **Install dependencies:**
    ```bash
    go mod tidy
    ```

4.  **Run Database Migrations:**
    This will create the `users` and `items` tables in your database.
    ```bash
    go run migratedb.go
    ```

5.  **Run the Application:**
    ```bash
    go run main.go
    ```
    The server will start on the port specified in your `.env` file (e.g., `http://localhost:3000`).

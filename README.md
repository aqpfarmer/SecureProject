# SecureProject

A secure, multi-project .NET solution for user management, authentication, and modern web UI.

## Solution Structure

- **SafeVault**: Blazor Server frontend for user login, profile management, and role-based navigation. Modern Bootstrap UI, JWT authentication, and session management.
- **SafeVaultApi**: ASP.NET Core WebAPI backend for user CRUD, authentication, and role management. Uses SQLite for storage, supports JWT, and enforces CORS for frontend integration.
- **SecureProject.Shared**: Shared class library for models (e.g., `User`) used by both frontend and backend, ensuring consistent data contracts.
- **SeedUsers**: .NET console app for seeding the database with initial users and roles. Run once to bootstrap the system.
- **SecureProject.Tests**: NUnit test project for API and integration tests, including authentication, user CRUD, and security validation.

## How Each Project Works

### SafeVault (Blazor Frontend)
- Login page authenticates users via API and stores JWT in localStorage.
- Authenticated page displays user info, allows editing email/password, and shows assigned roles.
- Navbar links are shown based on user roles; logout clears session and JWT.
- Uses Bootstrap for responsive, modern UI.

### SafeVaultApi (WebAPI Backend)
- `/api/auth/login`: Authenticates users, returns JWT.
- `/api/users`: CRUD endpoints for user management, protected by JWT and role-based authorization.
- Uses SQLite for persistent storage.
- CORS enabled for frontend integration.

### SecureProject.Shared
- Contains shared models (e.g., `User`) with attributes for JSON serialization.
- Used by both frontend and backend for type safety and consistency.

### SeedUsers
- Seeds the database with initial users and roles (Admin, Manager, etc.).
- Run once after setup: `dotnet run --project SeedUsers`

### SecureProject.Tests
- NUnit tests for API endpoints, authentication, and security.
- Validates login, user CRUD, and role-based access.

## Getting Started

1. **Build All Projects**
   ```
   dotnet build
   ```
2. **Seed the Database**
   ```
   dotnet run --project SeedUsers
   ```
3. **Run the API Backend**
   ```
   dotnet run --project SafeVaultApi
   ```
4. **Run the Blazor Frontend**
   ```
   dotnet run --project SafeVault
   ```
5. **Run Tests**
   ```
   dotnet test SecureProject.Tests
   ```

## Security Features
- JWT authentication and authorization
- Input validation and sanitization
- HTTPS enforced
- Role-based navigation and access control

## Extending
- Add new roles and pages by updating the shared model and API logic.
- Add new tests in `SecureProject.Tests` for coverage.
- Customize UI in `SafeVault` for branding or new features.

---

For more details, see each project's source code and comments.

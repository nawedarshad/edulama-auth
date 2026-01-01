# Edulama Auth Microservice

> **PROPERTY OF EDULAMA**
> 
> *This software and associated documentation files (the "Software") are the proprietary property of Edulama. Unauthorized copying, distribution, modification, or use of this file, via any medium, is strictly prohibited. This document is intended solely for internal use by authorized personnel.*

---

## 📖 About This Service

The **Edulama Auth Microservice** acts as the central **Identity and Access Management (IAM)** authority for the Edulama ecosystem. It is designed to handle multi-tenant authentication, ensuring secure and isolated access for thousands of schools and their respective users (Principals, Teachers, Students, Parents).

This service abstracts complex security protocols, allowing other microservices to remain lightweight by delegating identity verification to this centralized hub.

## 🏗 Architecture & How It Works

This microservice is built on a robust, scalable architecture prioritizing security and performance.

### Core Technology Stack
-   **Framework**: [NestJS](https://nestjs.com/) (Node.js) for modular, testable, and scalable server-side applications.
-   **Database**: PostgreSQL managed via [Prisma ORM](https://www.prisma.io/).
-   **Authentication**: Passport.js with JWT (JSON Web Tokens) strategies.
-   **Security**:
    -   **Argon2**: State-of-the-art password hashing.
    -   **Helmet**: Sets secure HTTP headers.
    -   **Throttler**: Rate limiting to prevent brute-force attacks.

### Workflow & Logic
1.  **Multi-Tenancy**: The system is designed from the ground up to be multi-tenant. Every user belongs to a `School` (Tenant). Authentication requests often require a `schoolCode` to resolve the correct tenant context.
2.  **Stateless Authentication**: Upon successful login, the service issues a **JWT (Access Token)**. This token contains encrypted claims (User ID, School ID, Role) that allow other services to verify identity without querying the database for every request.
3.  **Role-Based Access Control (RBAC)**: Users are assigned `Roles` (e.g., ADMIN, TEACHER), and Roles are granularly defined by `Permissions` and `UiFeatures`.
4.  **Audit Logging**: Critical actions (Login, Password Reset) are logged immutably in the `AuditLog` table for security compliance.

### Key Modules
-   **AuthModule**: Core logic for Login, Token Generation, and Context Switching.
-   **EmailModule**: Handles transactional emails (e.g., Password Reset) via SMTP/Nodemailer.
-   **PrismaModule**: Managing database connections and schema queries.

---

## 🚀 Setup & Installation

Follow these steps to set up the microservice locally for development.

### 1. Prerequisites
-   **Node.js**: v18 or higher.
-   **PostgreSQL**: A running postgres instance.
-   **npm**: Package manager.

### 2. Environment Configuration
Create a `.env` file in the root directory. You can pattern it after `.env.example` if available. Required variables include:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `PORT` | Port for the API to listen on | `4000` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/edulama_auth` |
| `JWT_SECRET` | Secret key for signing tokens | `super-secret-key-change-this` |
| `MAIL_HOST` | SMTP Host for emails | `smtp.example.com` |
| `MAIL_PORT` | SMTP Port | `587` |
| `MAIL_USER` | SMTP Username | `no-reply@edulama.com` |
| `MAIL_PASSWORD` | SMTP Password | `******` |
| `MAIL_FROM` | Default sender address | `Edulama Security <no-reply@edulama.com>` |

### 3. Installation
Install the project dependencies.
```bash
npm install
```

### 4. Database Setup
Ensure your PostgreSQL database is running, then apply migrations to create the schema.
```bash
npx prisma generate
npx prisma migrate dev
```

### 5. Running the Application

**Development Mode** (Hot-reload):
```bash
npm run start:dev
```

**Production Mode**:
```bash
npm run build
npm run start:prod
```

**Debug Mode**:
```bash
npm run start:debug
```

### 6. Testing
Run the test suite to ensure system integrity.
```bash
# Unit tests
npm run test

# End-to-end tests
npm run test:e2e
```

---

## 📡 API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` | Authenticate user with Email, Password, and SchoolCode. |
| `POST` | `/auth/forgot-password` | Trigger a password reset email. |
| `POST` | `/auth/reset-password` | Set a new password using a token. |
| `POST` | `/auth/verify` | Verify the validity of a JWT Access Token. |
| `GET` | `/auth/me` | Retrieve current user profile and school context. |
| `PATCH` | `/auth/switch-academic-year` | Switch the active academic year context. |
| `GET` | `/auth/health` | Health check probe. |

---

*For further technical details, please refer to the internal wiki or contact the Lead Architect.*

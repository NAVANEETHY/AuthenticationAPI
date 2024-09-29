# AuthenticationAPI

This project is a **User Authentication REST API** built using **ASP.NET Core Web API** with **MS SQL Server** as the database. The API uses **JWT (JSON Web Tokens)** for securing endpoints and provides user authentication and authorization. **SHA-512 hashing** is used for securely storing and verifying user passwords along with salt.

## Features

- **User Registration**: Create a new user by securely storing a password hash and salt using SHA-512.
- **User Login**: Authenticate users and issue JWT tokens for subsequent authorized access.
- **JWT Authorization**: Protect API endpoints using JWT tokens for authorization.
- **Stored Procedures**: The API uses stored procedures to interact with the SQL database for better performance and security.

## Technology Stack

- **ASP.NET Core Web API**: Backend framework for building the REST API.
- **MS SQL Server**: Relational database used to store user information.
- **JWT (JSON Web Tokens)**: For secure authentication and authorization.
- **SHA-512**: Used for password hashing and salting.

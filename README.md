# Sneckerball: Database-Driven Web Technology Project

Welcome to **Sneckerball**, a Flask-based web application showcasing a simple, database-driven snack bar reviewing platform. This codebase supports both standard browser-based interactions and a RESTful API.

This README provides an overview of the project structure, setup instructions, and usage guidelines.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Installation & Setup](#installation--setup)
5. [Running the Application](#running-the-application)
6. [Database Migrations](#database-migrations)
7. [API Usage](#api-usage)

---

## Project Overview

Sneckerball is a CRUD application developed for the **Information Science** course **Database Driven WebTechnology**. It demonstrates:

- **User registration and authentication** (via both Flask-Login for web and token-based authentication for API).
- **CRUD operations** on **Snackbars** (owner/admin-managed).
- **Review system** where users can write/edit/delete reviews.
- **Admin panel** to handle user and snackbar reports.
- **Soft-deletion** of users, snackbars, and reviews instead of hard deletion.
- **RESTful API** endpoints for each major component: users, snackbars, reviews, and authentication tokens.

---

## Features

1. **User Management**:
   - Register new users, login/logout, edit profiles, and view user details.
   - Admin flag to grant elevated privileges (delete snackbars, manage user accounts, handle reports, etc.).

2. **Snackbars**:
   - Owners can add and edit details of snackbars.
   - Other users can view snackbars, read or write reviews.

3. **Reviews**:
   - Users can post reviews about snackbars.
   - Reviews are soft-deleted when removed.

4. **Reporting System**:
   - Logged-in users can file reports on users or snackbars.
   - Admins can view all open reports, resolve or reject them, and optionally delete (soft-delete) the reported user or snackbar.

5. **REST API**:
   - Token-based authentication for most API routes.
   - Endpoints exist for users, snackbars, reviews, and tokens (login/revoke).

---

## Project Structure

Below is a simplified (excluded html and static files for brevity's sake) overview of the relevant files and folders:

```
.
├── .gitignore
├── DB.txt
├── html_bases.txt
├── README.md              <-- (Original README, not this merged file)
├── requirements.txt       <-- Python dependencies
├── sneckerball/
│   ├── .flaskenv          <-- Environment configuration for Flask (app & debug mode)
│   ├── sneckerball.py     <-- Main Flask entry point (Flask CLI uses this)
│   ├── config.py          <-- Config file (DB URI, secrets, etc.)
│   ├── app/
│   │   ├── __init__.py    <-- App factory-ish pattern & extension init
│   │   ├── templates/     <-- HTML templates for rendering web views
│   │   ├── static/        <-- Static files (CSS)
│   │   ├── errors.py      <-- Global error handlers
│   │   ├── forms.py       <-- WTForms for user input
│   │   ├── models.py      <-- SQLAlchemy models (User, Snackbar, Review, Report)
│   │   ├── routes.py      <-- Flask view functions for browser-based usage
│   │   ├── api/
│   │   │   ├── __init__.py <-- Initializes API blueprint and imports modules
│   │   │   ├── auth.py    <-- HTTP Basic/Token authentication
│   │   │   ├── errors.py  <-- API-level error handlers
│   │   │   ├── users.py   <-- Endpoints for user CRUD operations
│   │   │   ├── snackbars.py <-- Endpoints for managing snackbars
│   │   │   └── reviews.py <-- Endpoints for managing reviews
└── ...
```

---

## Installation & Setup

**Prerequisites**:
- Python 3.9 (recommended to match the environment used in the project)
- [pip](https://pypi.org/project/pip/) for installing dependencies
- [virtualenv](https://pypi.org/project/virtualenv/) or [Conda](https://www.anaconda.com/download) for environment management

**Steps**:
1. **Clone the repository**
2. **Create & activate a virtual environment**:

   Using virtualenv:
   ```bash
   python3.9 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

   Using Conda:
   ```bash
   conda create -n sneckerball python=3.9
   conda activate sneckerball
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set environment variables** *(optional)*:
   - By default, `.flaskenv` sets `FLASK_APP=sneckerball.py` and `FLASK_DEBUG=1`.
   - If you have a secret key, set them in your environment before running:
     ```bash
     export SECRET_KEY='some-strong-key'
     ```

---

## Running the Application

1. **Navigate to the `sneckerball` folder**:
   ```bash
   cd sneckerball
   ```

2. **Run the Flask app**:
   ```bash
   flask run
   ```
   By default, the application is accessible at [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Database Migrations

This project uses [Flask-Migrate](https://flask-migrate.readthedocs.io/en/latest/) to handle SQLAlchemy schema changes. Common commands:

- `flask db init` – initialize migrations folder.
- `flask db migrate -m "Your message"` – detect model changes and create a migration script.
- `flask db upgrade` – apply migrations to the database.
- `flask db downgrade` – revert to a previous migration.

---

## API Usage

Sneckerball provides a token-based API for programmatic interactions:

- **Token Authentication**:
  - **POST** `/api/tokens` with Basic Auth (username & password) to obtain a bearer token.
  - **DELETE** `/api/tokens` to revoke the current token.

- **Users**:
  - **POST** `/api/users` – Create a new user (no auth required).
  - **GET** `/api/users` – List all users (requires Bearer token).
  - **GET** `/api/users/<id>` – Retrieve user by ID (requires Bearer token).
  - **PUT** `/api/users/<id>` – Update user data (self or admin).
  - **DELETE** `/api/users/<id>` – Soft-delete user (self or admin).

- **Snackbars**:
  - **GET** `/api/snackbars` – Retrieve all non-deleted snackbars.
  - **GET** `/api/snackbars/<id>` – Single snackbar details.
  - **POST** `/api/snackbars` – Create a new snackbar (the requester is owner).
  - **PUT** `/api/snackbars/<id>` – Update an existing snackbar (owner or admin).
  - **DELETE** `/api/snackbars/<id>` – Soft-delete (owner or admin).

- **Reviews**:
  - **GET** `/api/reviews/<id>` – Retrieve a single review by ID.
  - **GET** `/api/snackbars/<id>/reviews` – All reviews for a specific snackbar.
  - **GET** `/api/users/<id>/reviews` – All reviews by a specific user.
  - **POST** `/api/snackbars/<id>/reviews` – Create a new review under a snackbar.
  - **PUT** `/api/reviews/<id>` – Update a review (author or admin).
  - **DELETE** `/api/reviews/<id>` – Soft-delete a review (author or admin).

Each request that *requires* authentication must include a header of the form:
```
Authorization: Bearer <token>
```

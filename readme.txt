JWT Authentication Server with SQLite Backend
Overview
This project implements a JWT authentication server that uses SQLite to store private keys. The private keys are persisted to disk, ensuring availability even if the server is restarted or moved.

Features
SQLite Database: Stores private keys in a SQLite database, ensuring secure and persistent storage.

JWT Signing: Signs JWTs using private keys retrieved from the database, providing secure authentication.

JWKS Endpoint: Serves a JWKS endpoint that clients can use to verify JWT signatures.

Endpoints
POST /auth: Reads a private key from the database and signs a JWT. If the expired query parameter is present, it uses an expired key.

GET /.well-known/jwks.json: Provides a JWKS response with all valid (non-expired) private keys from the database.

Installation

Clone the repository:
git clone <repository_url>

Install the required packages:
pip install -r requirements.txt

Usage

Start the server:


python main.py

The server will now listen on http://localhost:8080 for incoming requests.
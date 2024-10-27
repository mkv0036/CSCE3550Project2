"""Module for handling JWT authentication and key management."""
import base64
import json
import datetime
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import jwt

HOST_NAME = "localhost"
SERVER_PORT = 8080

# Connection to SQLite database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Drop the table if it exists
cursor.execute('DROP TABLE IF EXISTS keys')

# Create table with correct data types
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')

# Generate private keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize keys to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Get private key numbers
numbers = private_key.private_numbers()

# Set expiration times
current_time = datetime.datetime.now(datetime.timezone.utc)
one_hour_later = current_time + datetime.timedelta(hours=1)

# Insert keys into database with expiration times
try:
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (expired_pem, int(current_time.timestamp()))  # Expired
    )
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (pem, int(one_hour_later.timestamp()))  # Valid
    )
except Exception as e:
    pass

# Commit changes and close connection
conn.commit()
conn.close()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """HTTP Server for handling authentication requests."""
    def do_PUT(self):
        """Handles PUT requests."""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """Handles PATCH requests."""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Handles DELETE requests."""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Handles HEAD requests."""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        """Handles POST requests."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if parsed_path.path == "/auth":
            # Connect to the database
            try:
                with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
                    cursor = conn.cursor()
                    # Fetch the correct key based on expiration status
                    if 'expired' in params:
                        cursor.execute(
                            'SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1',
                            (int(current_time.timestamp()),)
                        )
                    else:
                        cursor.execute(
                            'SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1',
                            (int(current_time.timestamp()),)
                        )
                    key_row = cursor.fetchone()
                    if key_row:
                        key_pem = key_row[0]
                        try:
                            key = serialization.load_pem_private_key(key_pem, password=None)
                        except (ValueError, TypeError):
                            self.send_response(500)
                            self.send_header("Content-type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "No valid key found"}')
                            return
                        headers = {
                            "kid": "goodKID"
                        }
                        token_payload = {
                            "user": "username",
                            "exp": int((current_time + datetime.timedelta(hours=1)).timestamp())
                        }
                        if 'expired' in params:
                            headers["kid"] = "expiredKID"
                            token_payload["exp"] = int(
                                (current_time - datetime.timedelta(hours=1)).timestamp())
                        encoded_jwt = jwt.encode(
                            token_payload, pem, algorithm="RS256", headers=headers)
                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(bytes(json.dumps({'token': encoded_jwt}), "utf-8"))
                    else:
                        self.send_response(500)
                        self.send_header("Content-type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "No valid key found"}')
            except sqlite3.OperationalError:
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Database connection failed"}')
        else:
            self.send_response(405)
            self.end_headers()

    def do_GET(self):
        """Handles GET requests"""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()

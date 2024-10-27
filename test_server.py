import sqlite3
import pytest
import requests
from main import MyServer
from http.server import HTTPServer
from threading import Thread
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Helper function to create and start the server in a separate thread
def start_test_server():
    server = HTTPServer(('localhost', 8080), MyServer)
    thread = Thread(target=server.serve_forever)
    thread.daemon = True  # Allows the program to exit even if the thread is still running
    thread.start()
    time.sleep(1)  # Wait for a second to ensure the server is ready
    return server

# Helper function to generate a valid RSA key
def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

# Helper function to set up the database with a given expiration time
def setup_database(expiration_time, db_name='totally_not_my_privateKeys.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL)''')
    pem = generate_rsa_key()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiration_time))
    conn.commit()
    conn.close()

# Test for JWT creation with a valid key
def test_jwt_creation_valid():
    setup_database(9999999999)
    server = start_test_server()
    response = requests.post('http://localhost:8080/auth')
    assert response.status_code == 200
    data = response.json()
    assert 'token' in data
    server.shutdown()

# Test for JWT creation with an expired key
def test_jwt_creation_expired():
    setup_database(0)
    server = start_test_server()
    response = requests.post('http://localhost:8080/auth?expired=true')
    assert response.status_code == 200
    data = response.json()
    assert 'token' in data
    server.shutdown()

# Test for the JWKS endpoint
def test_jwks_endpoint():
    server = start_test_server()
    response = requests.get('http://localhost:8080/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.json()
    assert 'keys' in data
    assert len(data['keys']) > 0
    server.shutdown()

# Test invalid JWT creation request
def test_invalid_jwt_request():
    server = start_test_server()
    response = requests.post('http://localhost:8080/invalid')
    assert response.status_code == 405
    server.shutdown()

# Test JWT creation with no keys in the database
def test_jwt_creation_no_keys():
    db_name = 'totally_not_my_privateKeys.db'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL)''')
    cursor.execute('DELETE FROM keys')
    # Verify table is empty
    cursor.execute('SELECT * FROM keys')
    print(f"Keys table after delete: {cursor.fetchall()}")
    conn.commit()
    conn.close()

    server = start_test_server()
    response = requests.post('http://localhost:8080/auth')
    print(f"Response status: {response.status_code}")
    print(f"Response text: {response.text}")
    # Check that the response status is 500 (Internal Server Error)
    assert response.status_code == 500
    assert response.text == '{"error": "No valid key found"}'
    server.shutdown()

# Test for unsupported HTTP methods
def test_unsupported_methods():
    server = start_test_server()
    unsupported_methods = ['PUT', 'PATCH', 'DELETE', 'HEAD']
    for method in unsupported_methods:
        response = requests.request(method, 'http://localhost:8080/auth')
        assert response.status_code == 405
    server.shutdown()

# Test if key is in correct format
def test_invalid_key():
    db_name = 'totally_not_my_privateKeys.db'
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL)''')



# Test for unsupported HTTP methods (detailed)
def test_unsupported_methods_detailed():
    server = start_test_server()
    unsupported_methods = {
        'PUT': 405,
        'PATCH': 405,
        'DELETE': 405,
        'HEAD': 405
    }
    for method, expected_status in unsupported_methods.items():
        response = requests.request(method, 'http://localhost:8080/auth')
        assert response.status_code == expected_status
    server.shutdown()

def test_key_loading_failure():
    server = start_test_server()
    response = requests.post('http://localhost:8080/auth')
    assert response.status_code == 500  # Expecting failure due to no keys
    server.shutdown()


if __name__ == "__main__":
    pytest.main()

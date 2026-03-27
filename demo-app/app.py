"""
Intentionally vulnerable application for security scanning demonstration
DO NOT use this code in production!
"""

import sqlite3
import os
import pickle
import hashlib

# SQL Injection Vulnerability
def unsafe_query(user_input):
    """Demonstrates SQL injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

# Command Injection Vulnerability
def unsafe_command(filename):
    """Demonstrates command injection vulnerability"""
    # Vulnerable: Unsanitized input to os.system
    os.system(f"cat {filename}")

# Hardcoded Credentials
API_KEY = "sk-1234567890abcdef"
SECRET_KEY = "super_secret_key_123"
DATABASE_PASSWORD = "admin123"

# Weak Cryptography
def weak_hash(password):
    """Demonstrates weak cryptography"""
    # Vulnerable: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Insecure Deserialization
def unsafe_deserialize(data):
    """Demonstrates insecure deserialization"""
    # Vulnerable: pickle can execute arbitrary code
    return pickle.loads(data)

# Path Traversal
def read_file(filename):
    """Demonstrates path traversal vulnerability"""
    # Vulnerable: No path sanitization
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# Unvalidated Redirect
def redirect_user(url):
    """Demonstrates unvalidated redirect"""
    # Vulnerable: No URL validation
    return f"Location: {url}"

class User:
    def __init__(self, username, password):
        self.username = username
        # Vulnerable: Storing password in plaintext
        self.password = password
import os
from flask import Flask, render_template, request, url_for, redirect, jsonify, make_response
import pypyodbc as odbc
import secrets
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user
from functools import wraps
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import random
import array
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#using for RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as paddingRSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import base64

sender = "juanjoguti2020@gmail.com"

app_password = 'vndnghrvqredwkim'

# Database connection configuration
DRIVER_NAME = 'SQL SERVER'
DATABASE_NAME = 'SecurePurchase'

# JJ's Connection String
SERVER_NAME = 'LAPTOP-JP2PAISQ'
connection_string = f"""
    DRIVER={{{DRIVER_NAME}}};
    SERVER={SERVER_NAME};
    DATABASE={DATABASE_NAME};
    Trust_Connection=yes;
     uid=;
    pwd=;
"""

#connecting to the DB
def connect_to_database():
    conn = odbc.connect(connection_string)
    return conn

# Function to encrypt data AES-128 using cryptography
def encrypt_data(data):
    key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
    iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Function to decrypt data AES-128 using cryptography
def decrypt_data(ciphertext):
    key = b'\xfd\x91\xdb\xdc\x9d\x9a\xb5\x86\x18\xab\xf4\x9c\x85\xd1\x1d\xff'
    iv = b'\x82\x0b\xa9\x3d\x9b\x0e\x9a\x1c\x3c\xee\x4a\xf1\x98\x36\xcd\xd7'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
    backend=default_backend()
)

print("Object")
print(private_key)

print("\n Now just the bytes of the thing: \n")
# Serialize the private key into bytes
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print(private_key_bytes)

public_key = private_key.public_key()
print("\n pub key obj \n")
print(public_key)

# Serialize the public key into bytes
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\npub key bytes:\n")
print(public_key_bytes)

# Reconstruct the private key from the private bytes
# private_key_reconstructed = serialization.load_pem_private_key(
#     private_key_bytes,
#     password=None,
#     backend=default_backend()
# )

# print("\nReconstructed private key:")
# print(private_key_reconstructed)

# print("\n1 last test for PRK:\n")
# print(private_key_reconstructed.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# ))


# Reconstruct the public key from the public bytes
# public_key_reconstructed = serialization.load_pem_public_key(
#     public_key_bytes,
#     backend=default_backend()
# )

# print("\nReconstructed public key:")
# print(public_key_reconstructed)

# print("\n 1 last test public key:\n")
# print(public_key_reconstructed.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo)
#     )

conn = connect_to_database()
cursor = conn.cursor()

public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')
private_key_base64 = base64.b64encode(private_key_bytes).decode('utf-8')
#retrieve query now checking keys again
#updateQuery = "UPDATE Employees SET PublicKey = ?, PrivateKey = ? WHERE UserId = '59d55a2f208d23f8bb6ea8b183b5f943'"
#cursor.execute(updateQuery, ( public_key_base64, private_key_base64))

retrieveQuery = "SELECT PublicKey, PrivateKey FROM Employees WHERE UserId = '59d55a2f208d23f8bb6ea8b183b5f943'"
cursor.execute(retrieveQuery)
rows = cursor.fetchall()

rtrPubKey = rows[0][0]
rtrPrvKey = rows[0][1]

pubBytes = base64.b64decode(rtrPubKey)
prvBytes = base64.b64decode(rtrPrvKey)


print("\nRetrieved pub bytes k:\n")
print(pubBytes)
print("\nRetrieved prv bytes k:\n")
print(prvBytes)

print("\nNow building actual objects: \n")

print("\n Private Key object:")
recprvBytes = serialization.load_pem_private_key(
     prvBytes,
     password=None,
     backend=default_backend()
)
print(recprvBytes)

print("\n Public Key object:\n")
recpubBytes = serialization.load_pem_public_key(
     pubBytes,
     backend=default_backend()
)
print(recpubBytes)

# now actually trying to sign some shit

empName = "John"
item = "Staples"
price = "12.00"
quantity = "5"
employeeTimeReq = "2024-05-11"

strToHash = empName + item + price + quantity + employeeTimeReq

messageToSign = strToHash.encode('UTF-8')

# Sign the message using the private key
signature = recprvBytes.sign(
    messageToSign,
    paddingRSA.PSS(
        mgf=paddingRSA.MGF1(hashes.SHA256()),
        salt_length=paddingRSA.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


signatureBase64 = base64.b64encode(signature).decode('UTF-8')
print("\nSignature base 64 after decoding from UTF-8: \n")
print(signatureBase64)

print("\nNormal Signature which is probs hex: \n")
print(signature)

print("\n")
print(base64.b64decode(signatureBase64))


print("\n\nverification attempt")

valid_signature = False
try:
    recpubBytes.verify(
        signature,
        messageToSign,
        paddingRSA.PSS(
            mgf=paddingRSA.MGF1(hashes.SHA256()),
            salt_length=paddingRSA.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    valid_signature = True
    print("The signature is valid.")
except Exception as e:
    valid_signature = False
    print(f"An error occurred: {e}")

conn.commit()
conn.close()
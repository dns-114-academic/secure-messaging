# TP02 - Secure Messaging Client

import sys
import requests
from flask import Flask, request, jsonify, render_template_string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
import threading


app = Flask(__name__)

# Configuration
SERVER_URL = "http://127.0.0.1:5000"          # Key server address
MY_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5001   # Port from CLI arg or default
USERNAME = sys.argv[2] if len(sys.argv) > 2 else f"User{MY_PORT}"  # Username from CLI or default


# Global variables
my_key = RSA.generate(2048)                          # RSA key pair (private + public)
my_pub_key = my_key.publickey().export_key().decode('utf-8')  # Export the public key
rsa_cipher = PKCS1_OAEP.new(my_key)                 # Cipher object for RSA encrypt/decrypt

# Active session storage
current_session_key = None   # AES key
messages = []                # Chat history


def encrypt_aes(msg_text, key):
    """Encrypt a plaintext string with AES-CBC and return a base64 string (IV + ciphertext)."""
    cipher = AES.new(key, AES.MODE_CBC)
    # pad: adjust to block size before encrypting
    ct_bytes = cipher.encrypt(pad(msg_text.encode('utf-8'), AES.block_size))
    # Return IV + ciphertext concatenated and base64-encoded
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')


def decrypt_aes(b64_ct, key):
    """Decrypt a base64-encoded AES-CBC ciphertext (IV prepended) and return plaintext."""
    raw = base64.b64decode(b64_ct)
    iv = raw[:16]    # First 16 bytes → IV
    ct = raw[16:]    # Remainder → ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # unpad: remove padding added during encryption
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')


@app.route('/')
def index():
    """Serve the chat web interface."""
    with open("index.html", "r") as f:
        html_content = f.read()
    return render_template_string(html_content, username=USERNAME, port=MY_PORT)


@app.route('/send', methods=['POST'])
def send_message():
    """Send an encrypted message to the target client.
    If no session key exists yet, request one from the key server first.
    """
    global current_session_key
    data = request.json
    target_url = data.get('target_url')
    msg_content = data.get('message')

    if not current_session_key:
        print("[CLIENT] No session key found. Requesting from server...")

        target_name = data.get('target_name')

        # 1. Request a session from the key server
        resp = requests.post(f"{SERVER_URL}/session", json={"from": USERNAME, "to": target_name})
        if resp.status_code != 200:
            return jsonify({"error": "Session setup failed"})

        r_json = resp.json()

        # 2. Decrypt our copy of the AES key with our RSA private key
        enc_my_key = base64.b64decode(r_json['session_key_initiator_b64'])
        current_session_key = rsa_cipher.decrypt(enc_my_key)
        print(f"[CLIENT] AES key received and decrypted: {current_session_key.hex()}")

        # 3. Forward the target's encrypted copy to the peer client
        requests.post(f"{target_url}/receive_key", json={
            "session_key_b64": r_json['session_key_target_b64']
        })

    # Encrypt the message with the shared AES key
    encrypted_msg = encrypt_aes(msg_content, current_session_key)

    # Send directly to the peer client
    requests.post(f"{target_url}/receive_message", json={
        "sender": USERNAME,
        "ciphertext": encrypted_msg
    })

    # Store locally for display
    messages.append(f"[Me] {msg_content}")
    return jsonify({"status": "ok"})


@app.route('/receive_key', methods=['POST'])
def receive_key():
    """Receive the RSA-encrypted AES session key forwarded by the initiator."""
    global current_session_key
    data = request.json
    enc_key = base64.b64decode(data['session_key_b64'])
    # Decrypt with our RSA private key
    current_session_key = rsa_cipher.decrypt(enc_key)
    print(f"[CLIENT] AES key received (via peer) and decrypted: {current_session_key.hex()}")
    return jsonify({"status": "ok"})


@app.route('/receive_message', methods=['POST'])
def receive_message():
    """Receive an AES-encrypted message from a peer, decrypt it, and store it."""
    data = request.json
    sender = data.get('sender')
    ct = data.get('ciphertext')

    if current_session_key:
        try:
            clear_text = decrypt_aes(ct, current_session_key)
            messages.append(f"{sender}: {clear_text}")
            print(f"[RECEIVED] From {sender}: {clear_text} (Encrypted: {ct[:15]}...)")
        except Exception as e:
            print("Decryption error:", e)
    else:
        print("[ERROR] Message received without a session key!")

    return jsonify({"status": "received"})


@app.route('/messages')
def get_messages():
    """Return the full chat history as JSON."""
    return jsonify(messages)


def register_to_server():
    """Register this client's public key with the key server at startup."""
    try:
        print(f"[INIT] Registering {USERNAME} with the key server...")
        requests.post(f"{SERVER_URL}/register", json={
            "username": USERNAME,
            "public_key": my_pub_key
        })
        print("[INIT] Registration successful.")
    except Exception as e:
        print(f"[ERROR] Unable to reach the key server: {e}")


if __name__ == '__main__':
    register_to_server()
    app.run(port=MY_PORT)

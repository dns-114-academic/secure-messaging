# TP02 - Secure Messaging Server

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# HTTP server (creates the web app)
app = Flask(__name__)

# Client storage {"name": "pubkey"}
clients_db = {}


@app.route('/')
def home():
    return "Server OK."


@app.route('/register', methods=['POST'])
def register():
    """Register a client with their public key."""
    data = request.json          # retrieve data sent by client
    username = data.get('username')
    pub_key = data.get('public_key')

    if username and pub_key:
        clients_db[username] = pub_key
        print(f"[SERVER] Client registered: {username}")
        return jsonify({"status": "success", "message": f"{username} registered"})
    return jsonify({"status": "error", "message": "Missing data"})
    # Note: appending ", 400" would let Flask return HTTP 400 instead of the default 200


@app.route('/session', methods=['POST'])
def create_session():
    """AES key exchange: client1 requests a session with client2.
    The server generates a unique AES key and sends it to both clients,
    each copy encrypted with the respective client's RSA public key.
    """
    data = request.json
    initiator = data.get('from')  # who is requesting
    target = data.get('to')       # with whom

    # Verify both clients are known
    if initiator not in clients_db or target not in clients_db:
        return jsonify({"status": "error", "message": "Unknown client(s)"})

    print(f"[SERVER] Session request: {initiator} <-> {target}")

    # Generate a 16-byte AES session key
    session_key = get_random_bytes(16)

    # Encrypt the AES key for the initiator
    init_pub_key = RSA.import_key(clients_db[initiator])
    cipher_rsa_init = PKCS1_OAEP.new(init_pub_key)
    enc_key_init = cipher_rsa_init.encrypt(session_key)

    # Encrypt the AES key for the target
    target_pub_key = RSA.import_key(clients_db[target])
    cipher_rsa_target = PKCS1_OAEP.new(target_pub_key)
    enc_key_target = cipher_rsa_target.encrypt(session_key)

    # Return both encrypted keys
    return jsonify({
        "status": "success",
        "session_key_initiator_b64": base64.b64encode(enc_key_init).decode('utf-8'),
        "session_key_target_b64":    base64.b64encode(enc_key_target).decode('utf-8'),
    })


if __name__ == '__main__':
    # Start the server on port 5000
    app.run(port=5000, debug=True)

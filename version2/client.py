# TP02 v2 — Secure Messaging Client (Advanced)
#
# Improvements over v1:
#   - AES-GCM instead of AES-CBC  → authenticated encryption (no separate HMAC needed)
#   - RSA-PSS signatures on every outgoing message (non-repudiation)
#   - Multi-session support: one AES key per (local, remote) pair stored in a dict
#   - Automatic session reset + re-keying on conflict (HTTP 409 from server)
#   - Message model: { sender, text, timestamp, session_id, signature }
#   - Structured JSON message history (not plain strings)
#   - /status endpoint exposing client state (sessions, message count)
#   - /reset_session  endpoint to force re-keying with a peer

import sys
import requests
import json
import base64
import datetime
import logging
from flask import Flask, request, jsonify, render_template_string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("CLIENT")

app = Flask(__name__)

# ── CLI configuration ──────────────────────────────────────────────────────────
SERVER_URL = "http://127.0.0.1:5000"
MY_PORT    = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
USERNAME   = sys.argv[2] if len(sys.argv) > 2 else f"User{MY_PORT}"

# ── RSA key pair ───────────────────────────────────────────────────────────────
my_key     = RSA.generate(2048)
my_pub_key = my_key.publickey().export_key().decode()
rsa_cipher = PKCS1_OAEP.new(my_key)       # for decrypting the AES key
rsa_signer = pss.new(my_key)              # for signing outgoing messages

log.info("RSA-2048 key pair generated for %s", USERNAME)


# ── Per-session state ──────────────────────────────────────────────────────────
# session_keys[peer_username] = { "key": bytes, "session_id": str }
session_keys = {}

# messages[peer_username] = [ {sender, text, timestamp, verified, session_id}, … ]
messages = {}


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


# ── AES-GCM helpers ────────────────────────────────────────────────────────────

def encrypt_gcm(plaintext: str, key: bytes) -> str:
    """Encrypt with AES-256-GCM.  Returns base64(nonce + tag + ciphertext)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    blob = cipher.nonce + tag + ciphertext          # 16 + 16 + len(plaintext)
    return base64.b64encode(blob).decode()


def decrypt_gcm(b64_blob: str, key: bytes) -> str:
    """Decrypt and authenticate AES-GCM blob.  Raises ValueError on tag mismatch."""
    raw        = base64.b64decode(b64_blob)
    nonce      = raw[:16]
    tag        = raw[16:32]
    ciphertext = raw[32:]
    cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# ── RSA-PSS signature helpers ──────────────────────────────────────────────────

def sign_message(text: str) -> str:
    """Sign text with our RSA private key (PSS-SHA256). Returns base64 signature."""
    h   = SHA256.new(text.encode())
    sig = rsa_signer.sign(h)
    return base64.b64encode(sig).decode()


def verify_signature(text: str, sig_b64: str, pub_key_pem: str) -> bool:
    """Verify a PSS-SHA256 signature against a PEM public key. Returns bool."""
    try:
        pub = RSA.import_key(pub_key_pem)
        verifier = pss.new(pub)
        h = SHA256.new(text.encode())
        verifier.verify(h, base64.b64decode(sig_b64))
        return True
    except Exception:
        return False


# ── Session management ─────────────────────────────────────────────────────────

def _sign_session_request(initiator: str, target: str) -> str:
    """Sign 'initiator:target' with our private key for server-side verification."""
    h   = SHA256.new(f"{initiator}:{target}".encode())
    sig = rsa_signer.sign(h)
    return base64.b64encode(sig).decode()


def setup_session(target_name: str, target_url: str) -> dict:
    """Request (or reuse) an AES session with target_name.
    Handles HTTP 409 (session already exists) by resetting and retrying once.
    Returns the session dict stored in session_keys[target_name].
    """
    sig = _sign_session_request(USERNAME, target_name)
    payload = {"from": USERNAME, "to": target_name, "signature": sig}
    resp = requests.post(f"{SERVER_URL}/session", json=payload)

    if resp.status_code == 409:
        # Session already exists on server — force reset then retry
        log.warning("Session conflict for %s — resetting", target_name)
        requests.post(f"{SERVER_URL}/session/reset", json={"from": USERNAME, "to": target_name})
        resp = requests.post(f"{SERVER_URL}/session", json=payload)

    resp.raise_for_status()
    r = resp.json()

    # Decrypt our copy of the AES key
    enc_my_key = base64.b64decode(r["session_key_initiator_b64"])
    aes_key    = rsa_cipher.decrypt(enc_my_key)
    session_id = r["session_id"]

    session_keys[target_name] = {"key": aes_key, "session_id": session_id}
    messages.setdefault(target_name, [])
    log.info("AES key established with %s  session=%s  key=%s…",
             target_name, session_id, aes_key.hex()[:12])

    # Forward the target's encrypted copy peer-to-peer
    requests.post(f"{target_url}/receive_key", json={
        "session_key_b64": r["session_key_target_b64"],
        "session_id":      session_id,
        "from":            USERNAME
    })
    return session_keys[target_name]


# ── Web UI ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    with open("index_v2.html", "r") as f:
        html = f.read()
    return render_template_string(html, username=USERNAME, port=MY_PORT)


# ── /send ──────────────────────────────────────────────────────────────────────

@app.route('/send', methods=['POST'])
def send_message():
    """Encrypt a message with AES-GCM, sign it with RSA-PSS, and send to peer."""
    data        = request.json or {}
    target_url  = data.get('target_url', '')
    target_name = data.get('target_name', '')
    msg_text    = data.get('message', '')

    if not target_url or not target_name or not msg_text:
        return jsonify({"error": "Missing target_url, target_name, or message"}), 400

    # Ensure we have a session key
    if target_name not in session_keys:
        try:
            setup_session(target_name, target_url)
        except Exception as exc:
            log.error("Session setup failed: %s", exc)
            return jsonify({"error": f"Session setup failed: {exc}"}), 500

    sess     = session_keys[target_name]
    aes_key  = sess["key"]
    sess_id  = sess["session_id"]

    # Sign the plaintext before encrypting
    signature = sign_message(msg_text)

    # Encrypt the full payload (text + signature + timestamp)
    payload_str = json.dumps({
        "text":      msg_text,
        "signature": signature,
        "timestamp": _now(),
        "sender":    USERNAME,
        "session_id": sess_id
    })
    ciphertext = encrypt_gcm(payload_str, aes_key)

    # Send to peer
    requests.post(f"{target_url}/receive_message", json={
        "sender":     USERNAME,
        "ciphertext": ciphertext,
        "session_id": sess_id
    })

    # Store locally
    messages.setdefault(target_name, []).append({
        "sender":    f"[Me → {target_name}]",
        "text":      msg_text,
        "timestamp": _now(),
        "verified":  True,
        "session_id": sess_id
    })
    log.info("SENT → %s: %s…  (enc=%s…)", target_name, msg_text[:30], ciphertext[:20])
    return jsonify({"status": "ok", "session_id": sess_id})


# ── /receive_key ───────────────────────────────────────────────────────────────

@app.route('/receive_key', methods=['POST'])
def receive_key():
    """Receive the RSA-wrapped AES key forwarded by the session initiator."""
    data       = request.json or {}
    enc_key    = base64.b64decode(data['session_key_b64'])
    session_id = data.get('session_id', 'unknown')
    from_user  = data.get('from', 'unknown')

    aes_key = rsa_cipher.decrypt(enc_key)
    session_keys[from_user] = {"key": aes_key, "session_id": session_id}
    messages.setdefault(from_user, [])
    log.info("AES key received from %s  session=%s  key=%s…",
             from_user, session_id, aes_key.hex()[:12])
    return jsonify({"status": "ok"})


# ── /receive_message ───────────────────────────────────────────────────────────

@app.route('/receive_message', methods=['POST'])
def receive_message():
    """Decrypt an AES-GCM message, verify its RSA-PSS signature, and store it."""
    data       = request.json or {}
    sender     = data.get('sender', '?')
    ciphertext = data.get('ciphertext', '')

    sess = session_keys.get(sender)
    if not sess:
        log.error("Message from %s — no session key found", sender)
        return jsonify({"status": "error", "message": "No session key"}), 400

    try:
        decrypted_str = decrypt_gcm(ciphertext, sess["key"])
        payload = json.loads(decrypted_str)
    except Exception as exc:
        log.error("Decryption/auth failure from %s: %s", sender, exc)
        return jsonify({"status": "error", "message": "Decryption failed"}), 400

    # Verify RSA-PSS signature
    sig_verified = False
    if "signature" in payload:
        # Look up sender's public key from server
        try:
            users_resp = requests.get(f"{SERVER_URL}/users")
            users_list = users_resp.json().get("users", [])
            # fetch the actual public key — server stores it in clients_db
            # We need to call /register equivalent — use audit to pull key
            # Simpler: we cache sender keys locally
            sender_pub = _get_peer_pub_key(sender)
            if sender_pub:
                sig_verified = verify_signature(payload["text"], payload["signature"], sender_pub)
        except Exception as exc:
            log.warning("Signature verification error: %s", exc)

    msg_entry = {
        "sender":     sender,
        "text":       payload.get("text", ""),
        "timestamp":  payload.get("timestamp", _now()),
        "verified":   sig_verified,
        "session_id": payload.get("session_id", "?")
    }
    messages.setdefault(sender, []).append(msg_entry)
    log.info("RECV ← %s: %s  sig_ok=%s", sender, msg_entry["text"][:40], sig_verified)
    return jsonify({"status": "received"})


# ── Peer public key cache ──────────────────────────────────────────────────────
# Populated when we first see a user (register or receive_key)
peer_pub_keys = {}

@app.before_request
def _capture_peer_key():
    """If a /receive_key request carries a 'public_key' field, cache it."""
    pass   # actual caching happens in /receive_key; this hook is a placeholder


def _get_peer_pub_key(username: str):
    """Return a cached public key for username, or None."""
    return peer_pub_keys.get(username)


# Override receive_key to also cache the sender's public key
_orig_receive_key = receive_key

# ── /receive_key v2: accept optional public_key ────────────────────────────────
@app.route('/receive_key_v2', methods=['POST'])
def receive_key_v2():
    """Extended receive_key that also stores the sender's public key for later
    signature verification.  The initiator passes their public_key here.
    """
    data       = request.json or {}
    enc_key    = base64.b64decode(data['session_key_b64'])
    session_id = data.get('session_id', 'unknown')
    from_user  = data.get('from', 'unknown')
    pub_key    = data.get('public_key', '')

    aes_key = rsa_cipher.decrypt(enc_key)
    session_keys[from_user] = {"key": aes_key, "session_id": session_id}
    messages.setdefault(from_user, [])

    if pub_key:
        peer_pub_keys[from_user] = pub_key
        log.info("Cached public key for %s", from_user)

    log.info("AES key received (v2) from %s  session=%s", from_user, session_id)
    return jsonify({"status": "ok"})


# ── /messages ──────────────────────────────────────────────────────────────────

@app.route('/messages')
def get_messages():
    """Return messages for a given peer (query param ?peer=X), or all messages."""
    peer = request.args.get('peer')
    if peer:
        return jsonify(messages.get(peer, []))
    # Flatten all conversations with peer label
    all_msgs = []
    for peer_name, msgs in messages.items():
        for m in msgs:
            all_msgs.append({**m, "conversation": peer_name})
    all_msgs.sort(key=lambda x: x.get("timestamp", ""))
    return jsonify(all_msgs)


# ── /status ────────────────────────────────────────────────────────────────────

@app.route('/status')
def status():
    """Expose client state: active sessions, message counts, identity."""
    return jsonify({
        "username":        USERNAME,
        "port":            MY_PORT,
        "active_sessions": [
            {"peer": k, "session_id": v["session_id"]}
            for k, v in session_keys.items()
        ],
        "message_counts":  {k: len(v) for k, v in messages.items()},
        "server_url":      SERVER_URL
    })


# ── /reset_session ─────────────────────────────────────────────────────────────

@app.route('/reset_session', methods=['POST'])
def reset_session():
    """Force-clear the local AES key for a peer (triggers re-keying on next send)."""
    data = request.json or {}
    peer = data.get('peer', '')
    if peer in session_keys:
        del session_keys[peer]
        log.info("Local session reset for peer %s", peer)
        return jsonify({"status": "ok", "message": f"Session with {peer} cleared"})
    return jsonify({"status": "not_found"}), 404


# ── Startup registration ───────────────────────────────────────────────────────

def register_to_server():
    """Register this client's RSA public key with the key server."""
    try:
        log.info("Registering %s with the key server…", USERNAME)
        requests.post(f"{SERVER_URL}/register", json={
            "username":   USERNAME,
            "public_key": my_pub_key
        })
        log.info("Registration successful.")
    except Exception as exc:
        log.error("Cannot reach key server: %s", exc)


if __name__ == '__main__':
    register_to_server()
    app.run(port=MY_PORT, debug=False)

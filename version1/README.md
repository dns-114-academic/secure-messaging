# Secure Messaging — TP02

A minimal end-to-end encrypted chat application using **RSA + AES hybrid encryption**, implemented in Python/Flask with a browser-based UI.

---

## Directory tree

```
secure_messaging/
├── server.py       # Key distribution server (port 5000)
├── client.py       # Chat client / Flask app (port 5001 / 5002)
├── index.html      # Browser UI (served by client.py)
└── README.md
```

---

## Implemented components

| Component | File | Description |
|---|---|---|
| Key server | `server.py` | Stores RSA public keys; generates & distributes AES session keys |
| `/register` | `server.py` | Client registers its RSA public key on startup |
| `/session` | `server.py` | Generates a 16-byte AES key, encrypts it for both parties with RSA-OAEP |
| Chat client | `client.py` | Flask app exposing `/send`, `/receive_key`, `/receive_message`, `/messages` |
| AES-CBC helpers | `client.py` | `encrypt_aes` / `decrypt_aes` — IV prepended to ciphertext, base64 transport |
| Web UI | `index.html` | Vanilla JS chat interface; polls `/messages` every second |

---

## Requirements

- Python 3.8+
- Install dependencies:

```bash
pip install flask pycryptodome requests
```

---

## How to run

Open **three terminals** in the project directory:

```bash
# Terminal 1 — key server
python server.py

# Terminal 2 — Alice (port 5001)
python client.py 5001 Alice

# Terminal 3 — Bob (port 5002)
python client.py 5002 Bob
```

Then open two browser tabs:

- Alice: [http://127.0.0.1:5001](http://127.0.0.1:5001)
- Bob: [http://127.0.0.1:5002](http://127.0.0.1:5002)

Type a message in Alice's tab and send it — the UI auto-detects the counterpart. The terminal will display the encrypted ciphertext alongside the decrypted plaintext.

**Expected terminal output (Alice):**

```
[INIT] Registering Alice with the key server...
[INIT] Registration successful.
[CLIENT] No session key found. Requesting from server...
[CLIENT] AES key received and decrypted: 9bd12490bd2150...
[RECEIVED] From Bob: Hi Alice! (Encrypted: 6aJ3JWMx1GV1...)
```

---

## Key design notes

The system follows a **hybrid encryption** model: the trusted server acts solely as a key distribution centre and never relays message content. It generates a fresh 16-byte AES-CBC session key per conversation, encrypts one copy for each party under their RSA-2048/OAEP public key, and returns both ciphertexts. The initiating client decrypts its copy and forwards the target's encrypted copy peer-to-peer over HTTP. All subsequent messages travel directly between clients, encrypted with the shared AES key — the server is no longer involved. A notable security trade-off is that the server sees the AES key in plaintext at generation time; a zero-knowledge improvement would be a Diffie-Hellman key agreement.

---

## References

- PKCS #1 OAEP — [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017)
- PyCryptodome documentation — [https://pycryptodome.readthedocs.io](https://pycryptodome.readthedocs.io)
- Flask documentation — [https://flask.palletsprojects.com](https://flask.palletsprojects.com)

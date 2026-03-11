# Secure Communications & Encrypted Messaging

**Course project** | école d'ingénieurs — Nov.–Dec. 2025 | Python, Flask

## Overview

End-to-end encrypted messaging application with a Flask backend, covering cryptographic protocols, MITM attacks and RSA-based authentication.

## Cryptographic Protocols

- **Diffie-Hellman key exchange** over Flask
- **RSA encryption** — key generation, encryption/decryption, digital signatures
- **AES-128 sessions** — symmetric session key distribution via trusted server
- **SHA-256 integrity** — message authentication

## Attacks Demonstrated

- **Live MITM** via `mitmproxy` on unauthenticated DH exchange
- **RSA impersonation** — signature forgery without authentication
- **Replay attacks** on unprotected session tokens

## Architecture

```
secure-messaging/
├── server/           # Flask trusted server
│   ├── app.py
│   └── key_distribution.py
├── client/           # Client app
│   ├── client.py
│   └── crypto.py
└── attacks/          # MITM & impersonation demos
    ├── mitm.py
    └── rsa_forgery.py
```

## Stack

`Python` · `Flask` · `pycryptodome` · `mitmproxy`

---

*Academic project — école d'ingénieurs*

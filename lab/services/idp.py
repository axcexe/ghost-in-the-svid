"""Mock human IdP. Stands in for Keycloak / PingOne AIC / Entra.

  python -m services.idp init           -> generate signing keys
  python -m services.idp issue <user>   -> print a signed user access token

In a real deployment this is your workforce IdP, and the broker's exchange is an
RFC 8693 token exchange (subject_token=user token, actor=agent identity).
"""
from __future__ import annotations

import os
import sys
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PRIV = "/lab/run/idp_priv.pem"
PUB = "/lab/run/idp_pub.pem"
ISSUER = "https://idp.lab.local"
AUDIENCE = "lab-agent-platform"

USERS = {
    "alice": {"roles": ["employee"]},
    "bob": {"roles": ["employee"]},
    "dana": {"roles": ["employee", "hr_admin"]},
}


def init():
    key = ec.generate_private_key(ec.SECP256R1())
    with open(PRIV, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(PRIV, 0o600)
    with open(PUB, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(PUB, 0o644)


def issue(user: str) -> str:
    with open(PRIV, "rb") as f:
        key = f.read()
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": user, "roles": USERS[user]["roles"],
              "iat": now, "exp": now + 600, "jti": str(uuid.uuid4())}
    return jwt.encode(claims, key, algorithm="ES256")


def verify(token: str) -> dict:
    with open(PUB, "rb") as f:
        pub = f.read()
    return jwt.decode(token, pub, algorithms=["ES256"], audience=AUDIENCE, issuer=ISSUER)


if __name__ == "__main__":
    if sys.argv[1] == "init":
        init()
    elif sys.argv[1] == "issue":
        print(issue(sys.argv[2]))

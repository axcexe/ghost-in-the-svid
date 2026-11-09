"""Thin helpers over the SPIFFE Workload API (py-spiffe) plus mTLS plumbing.

Everything in the lab gets its identity from the local SPIRE agent socket.
No workload holds a static secret.
"""
from __future__ import annotations

import base64
import hashlib
import os
import ssl
import tempfile
import time
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient

SOCKET = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock")
TRUST_DOMAIN = "lab.local"

DATA_API_ID = f"spiffe://{TRUST_DOMAIN}/svc/data-api"
BROKER_ID = f"spiffe://{TRUST_DOMAIN}/svc/broker"


class NoIdentity(Exception):
    """The Workload API would not issue this process an SVID."""


def _retry(fn, retries: float, what: str):
    last = None
    deadline = time.time() + retries
    while True:
        client = WorkloadApiClient(SOCKET)
        try:
            return fn(client)
        except Exception as e:  # noqa: BLE001 - py-spiffe raises several error types
            last = e
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        if time.time() >= deadline:
            raise NoIdentity(f"{what}: {type(last).__name__}: {last}")
        time.sleep(1)


def fetch_x509_context(retries: float = 30):
    return _retry(lambda c: c.fetch_x509_context(), retries, "fetch_x509_context")


def fetch_jwt_svid(audience: str, retries: float = 30) -> str:
    svid = _retry(lambda c: c.fetch_jwt_svid(audience={audience}), retries, "fetch_jwt_svid")
    return svid.token


def whoami(retries: float = 30) -> str:
    ctx = fetch_x509_context(retries)
    return str(ctx.default_svid.spiffe_id)


def validate_jwt_svid(token: str, audience: str) -> str:
    """Validate a JWT-SVID through the Workload API and return its SPIFFE ID."""
    client = WorkloadApiClient(SOCKET)
    try:
        svid = client.validate_jwt_svid(token=token, audience=audience)
        return str(svid.spiffe_id)
    finally:
        client.close()


# ---------------------------------------------------------------- mTLS ------

@dataclass
class TlsFiles:
    chain: str
    key: str
    bundle: str
    spiffe_id: str
    leaf_der: bytes


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _bundle_authorities(ctx):
    """Collect trust anchors from an X509Context across py-spiffe versions."""
    bs = ctx.x509_bundle_set
    bundles = []
    for attr in ("bundles", "_bundles"):
        val = getattr(bs, attr, None)
        if callable(val):
            val = val()
        if isinstance(val, dict):
            val = list(val.values())
        if val:
            bundles = list(val)
            break
    if not bundles:
        bundles = [bs.get_bundle_for_trust_domain(ctx.default_svid.spiffe_id.trust_domain)]
    out = []
    for b in bundles:
        out.extend(b.x509_authorities)
    return out


def write_tls_files(retries: float = 30) -> TlsFiles:
    ctx = fetch_x509_context(retries)
    svid = ctx.default_svid
    d = tempfile.mkdtemp(prefix="svid-")
    os.chmod(d, 0o700)
    chain = os.path.join(d, "chain.pem")
    key = os.path.join(d, "key.pem")
    bundle = os.path.join(d, "bundle.pem")
    with open(chain, "wb") as f:
        f.write(b"".join(_pem(c) for c in svid.cert_chain))
    with open(key, "wb") as f:
        f.write(
            svid.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    os.chmod(key, 0o600)
    with open(bundle, "wb") as f:
        f.write(b"".join(_pem(c) for c in _bundle_authorities(ctx)))
    leaf_der = svid.cert_chain[0].public_bytes(serialization.Encoding.DER)
    return TlsFiles(chain, key, bundle, str(svid.spiffe_id), leaf_der)


def server_context(t: TlsFiles, require_client_cert: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(t.chain, t.key)
    ctx.load_verify_locations(t.bundle)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return ctx


def client_context(t: TlsFiles | None, bundle: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # SPIFFE IDs live in URI SANs; we check them ourselves.
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(bundle or t.bundle)
    if t is not None:
        ctx.load_cert_chain(t.chain, t.key)
    return ctx


def spiffe_id_from_der(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    return uris[0] if uris else ""


def thumbprint(der: bytes) -> str:
    """RFC 8705 x5t#S256: base64url(SHA-256(DER cert)), unpadded."""
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

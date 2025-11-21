"""
wallet_keystore.py
Cold Wallet – Key Management Module (Part A)
Cryptography 2026-1
--------------------------------------------------------
Implements:
    - Ed25519 key generation
    - Argon2id-based key derivation
    - AES-256-GCM encryption for private key storage
    - Keystore JSON format required by the project
    - File checksum (SHA-256)
    - Bitcoin-style address derivation (SHA256 → RIPEMD160)
--------------------------------------------------------
"""

import os
import json
import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2.low_level import hash_secret_raw, Type as Argon2Type


# ================================================================
# Base64 Helpers
# ================================================================

def _b64e(data: bytes) -> str:
    """Encode bytes to Base64 ASCII string."""
    return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
    """Decode Base64 ASCII string to bytes."""
    return base64.b64decode(data_b64.encode("ascii"))


# ================================================================
# KDF: Argon2id
# ================================================================

def derive_encryption_key(passphrase: str,
                          salt: bytes,
                          t_cost: int = 3,
                          m_cost: int = 64 * 1024,
                          p: int = 1):
    """
    Derives a 256-bit AES key using Argon2id.
    Returns:
        aes_key : 32-byte key
        kdf_params : dict (serializable)
    """
    aes_key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=p,
        hash_len=32,
        type=Argon2Type.ID,
    )

    return aes_key, {
        "salt_b64": _b64e(salt),
        "t_cost": t_cost,
        "m_cost": m_cost,
        "p": p,
    }


# ================================================================
# AEAD: AES-256-GCM
# ================================================================

def encrypt_private_key(aes_key: bytes, private_key_bytes: bytes):
    """
    Encrypts a private key using AES-256-GCM.
    Returns: (nonce, ciphertext, tag)
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, private_key_bytes, None)

    return nonce, ct[:-16], ct[-16:]  # ciphertext, tag


def decrypt_private_key(aes_key: bytes,
                        nonce: bytes,
                        ciphertext: bytes,
                        tag: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# ================================================================
# Address Derivation (Bitcoin-style)
# ================================================================

def derive_address(pubkey_bytes: bytes) -> str:
    """
    Address = RIPEMD-160(SHA-256(pubkey)), hex string.
    """
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return ripe.hex()


# ================================================================
# Keystore Creation
# ================================================================

def create_keystore(passphrase: str) -> dict:
    """
    Generates:
        - Ed25519 keypair
        - KDF parameters + derived AES key
        - Encrypted private key
        - Address, pubkey, metadata
        - Checksum (SHA-256)
    Returns: dict compatible with the project specification.
    """

    # 1. Ed25519 key generation
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # 2. Argon2id key derivation
    salt = os.urandom(16)
    aes_key, kdf_params = derive_encryption_key(passphrase, salt)

    # 3. Encrypt private key
    nonce, ciphertext, tag = encrypt_private_key(aes_key, private_key_bytes)

    # Zeroization (best-effort)
    del aes_key

    # 4. Address from public key
    address = derive_address(pubkey_bytes)

    # 5. Build keystore (without checksum)
    keystore = {
        "kdf": "Argon2id",
        "kdf_params": kdf_params,
        "cipher": "AES-256-GCM",
        "cipher_params": {
            "nonce_b64": _b64e(nonce)
        },
        "ciphertext_b64": _b64e(ciphertext),
        "tag_b64": _b64e(tag),
        "pubkey_b64": _b64e(pubkey_bytes),
        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scheme": "Ed25519",
        "address": address,
    }

    # 6. Add checksum
    ks_bytes = json.dumps(
        keystore, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    checksum = hashlib.sha256(ks_bytes).hexdigest()
    keystore["checksum"] = f"SHA256:{checksum}"

    return keystore


# ================================================================
# Keystore File I/O
# ================================================================

def save_keystore(keystore: dict, path: str):
    """Write keystore to disk (UTF-8 JSON)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(keystore, f, indent=2, sort_keys=True)


def load_keystore(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ================================================================
# Private Key Recovery
# ================================================================

def load_private_key(keystore: dict, passphrase: str):
    """
    Verifies checksum, re-derives key, decrypts private key.
    Returns Ed25519PrivateKey object.
    """

    # 1. Checksum verification
    stored_sum = keystore["checksum"].split(":", 1)[1]
    tmp = dict(keystore)
    tmp.pop("checksum")

    recalculated = hashlib.sha256(
        json.dumps(tmp, sort_keys=True, separators=(",", ":"))
        .encode("utf-8")
    ).hexdigest()

    if recalculated != stored_sum:
        raise ValueError("Keystore integrity check failed.")

    # 2. Re-derive AES key
    params = keystore["kdf_params"]
    salt = _b64d(params["salt_b64"])

    aes_key, _ = derive_encryption_key(
        passphrase,
        salt,
        params["t_cost"],
        params["m_cost"],
        params["p"],
    )

    # 3. Decrypt private key
    nonce = _b64d(keystore["cipher_params"]["nonce_b64"])
    ciphertext = _b64d(keystore["ciphertext_b64"])
    tag = _b64d(keystore["tag_b64"])

    private_key_bytes = decrypt_private_key(aes_key, nonce, ciphertext, tag)

    # Zeroize AES key (best effort)
    del aes_key

    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)


# ================================================================
# CLI (Simple Demo for Part A Only)
# ================================================================

if __name__ == "__main__":
    print("\n=== Cold Wallet – Part A: Key Management ===")
    passphrase = input("Enter passphrase: ")

    ks = create_keystore(passphrase)
    filename = "keystore.json"
    save_keystore(ks, filename)

    print("\nKeystore successfully created.")
    print(f"→ File: {filename}")
    print(f"→ Address: {ks['address']}")
    print(f"→ Public Key (Base64): {ks['pubkey_b64']}")
    print("===========================================\n")


import os
import json
import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2.low_level import hash_secret_raw, Type as Argon2Type


# --------------------- Utilidades Base64 ------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


# --------------------- Derivación Argon2id ------------------------

def derive_key_argon2id(passphrase: str, salt: bytes,
                        t_cost: int = 3,
                        m_cost: int = 64 * 1024,
                        p: int = 1):
    """
    Deriva una clave de 32 bytes desde una passphrase usando Argon2id.
    """
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost,
        parallelism=p,
        hash_len=32,
        type=Argon2Type.ID,
    )

    params = {
        "salt_b64": b64e(salt),
        "t_cost": t_cost,
        "m_cost": m_cost,
        "p": p,
    }

    return key, params


# ----------------- Cifrado / Descifrado AES-256-GCM --------------

def encrypt_private_key(aes_key: bytes, private_key_bytes: bytes):
    """
    Cifra la llave privada con AES-256-GCM.
    Devuelve: (nonce, ciphertext, tag)
    """
    nonce = os.urandom(12)  # tamaño recomendado para GCM
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, private_key_bytes, None)

    ciphertext = ct[:-16]  # los últimos 16 bytes son el TAG
    tag = ct[-16:]

    return nonce, ciphertext, tag


def decrypt_private_key(aes_key: bytes, nonce: bytes,
                        ciphertext: bytes, tag: bytes):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# ------------- Derivación de dirección (estilo Bitcoin) ------------

def pubkey_to_address(pubkey_bytes: bytes) -> str:
    """
    Dirección = RIPEMD-160(SHA-256(pubkey)) en hexadecimal.
    Cumple con: "Persist public keys and a derived address".
    """
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return ripe.hex()


# ------------------- Creación del Keystore ----------------------

def create_keystore(passphrase: str) -> dict:
    # 1. Generar par de llaves Ed25519
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

    # 2. Derivar clave de cifrado con Argon2id
    salt = os.urandom(16)
    aes_key, kdf_params = derive_key_argon2id(passphrase, salt)

    # 3. Cifrar la llave privada con AES-256-GCM
    nonce, ciphertext, tag = encrypt_private_key(aes_key, private_key_bytes)

    # 4. Derivar dirección a partir del public key
    address = pubkey_to_address(pubkey_bytes)

    # 5. Timestamp (formato local ISO)
    created_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # 6. Crear keystore SIN checksum aún
    keystore = {
        "kdf": "Argon2id",
        "kdf_params": kdf_params,
        "cipher": "AES-256-GCM",
        "cipher_params": {"nonce_b64": b64e(nonce)},
        "ciphertext_b64": b64e(ciphertext),
        "tag_b64": b64e(tag),
        "pubkey_b64": b64e(pubkey_bytes),
        "created": created_time,
        "scheme": "Ed25519",
        "address": address  # requerido por la consigna (derived address)
    }

    # 7. Crear checksum SHA-256 del archivo (sin el propio checksum)
    keystore_bytes = json.dumps(
        keystore,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    checksum = hashlib.sha256(keystore_bytes).hexdigest()
    keystore["checksum"] = f"SHA256:{checksum}"

    return keystore


# ------------------- Guardar / Cargar JSON -------------------------

def save_keystore(keystore: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(keystore, f, indent=2, sort_keys=True)


def load_keystore(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ------ Cargar y descifrar privada (necesario para parte B luego) --

def load_private_key_from_keystore(keystore: dict, passphrase: str):
    """
    Verifica el checksum, re-deriva la clave AES con Argon2id
    y descifra la llave privada almacenada.
    """
    # 1. Verificación de checksum
    checksum_stored = keystore.get("checksum")
    if not checksum_stored or not checksum_stored.startswith("SHA256:"):
        raise ValueError("Checksum faltante o inválido.")

    checksum_value = checksum_stored.split(":", 1)[1]

    # Recalcular checksum sin el campo checksum
    keystore_copy = dict(keystore)
    keystore_copy.pop("checksum", None)

    keystore_bytes = json.dumps(
        keystore_copy,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    checksum_calc = hashlib.sha256(keystore_bytes).hexdigest()

    if checksum_calc != checksum_value:
        raise ValueError("El archivo del keystore fue modificado o está corrupto.")

    # 2. Re-derivar clave AES desde la passphrase y el salt
    kdf_params = keystore["kdf_params"]
    salt = b64d(kdf_params["salt_b64"])

    aes_key, _ = derive_key_argon2id(
        passphrase,
        salt,
        t_cost=kdf_params["t_cost"],
        m_cost=kdf_params["m_cost"],
        p=kdf_params["p"],
    )

    # 3. Recuperar parámetros de cifrado
    nonce = b64d(keystore["cipher_params"]["nonce_b64"])
    ciphertext = b64d(keystore["ciphertext_b64"])
    tag = b64d(keystore["tag_b64"])

    # 4. Descifrar bytes de la private key
    private_key_bytes = decrypt_private_key(aes_key, nonce, ciphertext, tag)

    # 5. Reconstruir objeto Ed25519
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key


# --------------------- Programa Principal -------------------------

if __name__ == "__main__":
    # Solicitar passphrase al usuario
    passphrase = input("Ingrese una passphrase: ")

    # Crear el keystore (Parte A)
    keystore = create_keystore(passphrase)

    # Guardar archivo
    filename = "keystore_A.json"
    save_keystore(keystore, filename)

    print("Keystore creado correctamente (Parte A).")
    print(f"Archivo generado: {filename}")
    print(f"Dirección derivada (Bitcoin-style): {keystore['address']}")
    print(f"Public key (base64): {keystore['pubkey_b64']}")

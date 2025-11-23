"""
wallet_transactions.py
Cold Wallet – Part B: Transaction Model + Signing
Cryptography 2026-1
"""

import json
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519

from wallet_A import (
    load_keystore,
    load_private_key,
    _b64e     
)


# ================================================================
# Canonical JSON (clave para firmar)
# ================================================================

def canonical_json(data: dict) -> bytes:
    """
    Canonical JSON:
    - Claves ordenadas
    - Sin espacios
    - UTF-8
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ================================================================
# Transaction Model
# ================================================================

class Transaction:
    def __init__(self,
                 from_addr: str,
                 to_addr: str,
                 value: str,
                 nonce: int,
                 gas_limit: int = None,
                 data_hex: str = "",
                 timestamp: str = None):

        self.from_addr = from_addr
        self.to_addr = to_addr
        self.value = str(value)
        self.nonce = int(nonce)
        self.gas_limit = gas_limit
        self.data_hex = data_hex
        self.timestamp = timestamp or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        tx = {
            "from": self.from_addr,
            "to": self.to_addr,
            "value": self.value,
            "nonce": str(self.nonce),
            "timestamp": self.timestamp,
        }

        if self.gas_limit is not None:
            tx["gas_limit"] = str(self.gas_limit)

        if self.data_hex:
            tx["data_hex"] = self.data_hex

        return tx

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


# ================================================================
# Signing Engine
# ================================================================

class Signer:

    @staticmethod
    def sign_transaction(keystore_path: str,
                         passphrase: str,
                         tx: Transaction) -> dict:

        # 1. Cargar keystore desde wallet_A
        ks = load_keystore(keystore_path)

        # 2. Recuperar private key desde wallet_A
        private_key = load_private_key(ks, passphrase)

        # 3. Canonical JSON
        msg = tx.canonical_bytes()

        # 4. Firma Ed25519
        signature = private_key.sign(msg)

        # 5. Paquete SignedTx
        signed = {
            "tx": tx.to_dict(),
            "sig_scheme": "Ed25519",
            "signature_b64": _b64e(signature),
            "pubkey_b64": ks["pubkey_b64"],
        }

        return signed


# ================================================================
# CLI DEMO
# ================================================================

if __name__ == "__main__":
    print("\n=== Cold Wallet – Part B: Signing Transactions ===")

    keystore_path = input("Keystore path: ").strip()
    passphrase = input("Enter passphrase: ").strip()

    from_addr = input("From address: ").strip()
    to_addr = input("To address: ").strip()
    value = input("Value: ").strip()
    nonce = int(input("Nonce: ").strip())

    gas = input("Gas limit (optional): ").strip()
    gas_limit = int(gas) if gas else None

    data_hex = input("Data hex (optional): ").strip()

    tx = Transaction(
        from_addr=from_addr,
        to_addr=to_addr,
        value=value,
        nonce=nonce,
        gas_limit=gas_limit,
        data_hex=data_hex,
    )

    signed_tx = Signer.sign_transaction(keystore_path, passphrase, tx)

    outname = "signed_tx.json"
    with open(outname, "w", encoding="utf-8") as f:
        json.dump(signed_tx, f, indent=2, sort_keys=True)

    print(f"\nSigned transaction saved as {outname}")


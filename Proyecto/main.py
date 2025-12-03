"""
main.py
Cold Wallet - Aplicación CLI Principal
Cryptography 2026-1
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

# Importar módulos existentes
from wallet_A import create_keystore, save_keystore, load_keystore, validate_passphrase
from wallet_transactions import Transaction, Signer
from wallet_verifier import load_signed_file, canonical_signed_json, process_transaction


class ColdWalletCLI:
    def __init__(self):
        self.keystore_path = "keystore.json"
        self.outbox_dir = "outbox"
        self.inbox_dir = "inbox"
        self.verified_dir = "verified"
        
        # Crear directorios si no existen
        Path(self.outbox_dir).mkdir(exist_ok=True)
        Path(self.inbox_dir).mkdir(exist_ok=True)
        Path(self.verified_dir).mkdir(exist_ok=True)
        
        self.nonce_tracker = {}

    def init(self):
        """Crear nuevo keystore"""
        print("\n=== Crear Nuevo Keystore ===")
        
        while True:
            passphrase = input("Ingrese contraseña (debe incluir 1 mayúscula y 1 símbolo): ")
            
            if validate_passphrase(passphrase):
                confirm = input("Confirmar contraseña: ")
                if passphrase == confirm:
                    break
                else:
                    print("Las contraseñas no coinciden\n")
            else:
                print("Contraseña inválida. Debe contener:")
                print("   - Una letra mayúscula (A-Z)")
                print("   - Un símbolo (!@#$%*/ etc.)\n")
        
        keystore = create_keystore(passphrase)
        save_keystore(keystore, self.keystore_path)
        
        print(f"\n Keystore creado exitosamente en {self.keystore_path}")
        print(f" Dirección: {keystore['address']}")
        print(f"Clave pública (Base64): {keystore['pubkey_b64']}")

    def address(self):
        """Mostrar dirección del keystore"""
        try:
            keystore = load_keystore(self.keystore_path)
            print(f"\n Dirección: {keystore['address']}")
            print(f" Clave pública (Base64): {keystore['pubkey_b64']}")
            print(f" Creado: {keystore['created']}")
        except Exception as e:
            print(f" Error: {e}")
            print("   Ejecute 'wallet init' primero")

    def sign(self, args):
        """Firmar transacción"""
        try:
            # Cargar keystore
            ks = load_keystore(self.keystore_path)
            passphrase = input("Ingrese contraseña para firmar: ")
            
            # Crear transacción
            tx = Transaction(
                from_addr=ks["address"],
                to_addr=args.to_addr,
                value=args.value,
                nonce=int(args.nonce),
                gas_limit=int(args.gas) if args.gas else None,
                data_hex=args.data if args.data else ""
            )
            
            # Firmar
            signer = Signer()
            signed_tx = signer.sign_transaction(self.keystore_path, passphrase, tx)
            
            # Guardar en outbox
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.outbox_dir}/signed_tx_{timestamp}.json"
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(signed_tx, f, indent=2, sort_keys=True)
            
            print(f"\n Transacción firmada y guardada en: {filename}")
            print(f" Hash (SHA256): {hashlib.sha256(json.dumps(signed_tx).encode()).hexdigest()[:16]}...")
            
        except Exception as e:
            print(f"Error: {e}")

    def recv(self, args):
        """Verificar transacción recibida"""
        try:
            from wallet_verifier import nonce_tracker
            self.nonce_tracker = nonce_tracker
            
            if os.path.isdir(args.path):
                # Procesar todos los archivos en el directorio
                files = [f for f in Path(args.path).glob("*.json") if f.is_file()]
                if not files:
                    print(f" No hay archivos JSON en {args.path}")
                    return
                    
                for file_path in files:
                    print(f"\n Procesando: {file_path.name}")
                    self._verify_single_tx(str(file_path))
            else:
                # Procesar archivo único
                self._verify_single_tx(args.path)
                
        except Exception as e:
            print(f" Error: {e}")

    def _verify_single_tx(self, tx_path):
        """Verificar una única transacción"""
        result = load_signed_file(tx_path)
        
        if result is None:
            print(" Transacción rechazada (error de formato)")
            return
        
        tx_dict, pubkey_bytes, signature_bytes = result
        canonical_tx = canonical_signed_json(tx_dict)
        
        # Usar el tracker de nonce del módulo verifier
       
        
        if process_transaction(tx_dict, pubkey_bytes, signature_bytes, canonical_tx):
            # Mover a directorio verified
            dest = Path(self.verified_dir) / Path(tx_path).name
            Path(tx_path).rename(dest)
            print(f" Transacción aceptada y movida a: {dest}")
        else:
            print("Transacción rechazada")

    def list(self):
        """Listar transacciones en directorios"""
        print("\n=== Transacciones Pendientes (inbox) ===")
        for file in Path(self.inbox_dir).glob("*.json"):
            print(f"   {file.name}")
        
        print("\n=== Transacciones Verificadas ===")
        for file in Path(self.verified_dir).glob("*.json"):
            print(f"   {file.name}")
        
        print("\n=== Transacciones Enviadas (outbox) ===")
        for file in Path(self.outbox_dir).glob("*.json"):
            print(f"   {file.name}")

    def status(self):
        """Mostrar estado del wallet"""
        print("\n=== Estado del Cold Wallet ===")
        
        # Verificar keystore
        if Path(self.keystore_path).exists():
            try:
                ks = load_keystore(self.keystore_path)
                print(f" Keystore: {self.keystore_path}")
                print(f"   Dirección: {ks['address']}")
                print(f"   Esquema: {ks['scheme']}")
            except:
                print(f" Keystore corrupto: {self.keystore_path}")
        else:
            print(f" Keystore no encontrado: {self.keystore_path}")
        
        # Contar archivos
        print(f"\n Directorios:")
        print(f"   inbox/: {len(list(Path(self.inbox_dir).glob('*.json')))} archivos")
        print(f"   outbox/: {len(list(Path(self.outbox_dir).glob('*.json')))} archivos")
        print(f"   verified/: {len(list(Path(self.verified_dir).glob('*.json')))} archivos")


def main():
    parser = argparse.ArgumentParser(description="Cold Wallet CLI")
    subparsers = parser.add_subparsers(dest="command", help="Comandos")
    
    # Comando init
    subparsers.add_parser("init", help="Crear nuevo keystore")
    
    # Comando address
    subparsers.add_parser("address", help="Mostrar dirección pública")
    
    # Comando sign
    sign_parser = subparsers.add_parser("sign", help="Firmar transacción")
    sign_parser.add_argument("--to", dest="to_addr", required=True, help="Dirección destino")
    sign_parser.add_argument("--value", required=True, help="Valor a transferir")
    sign_parser.add_argument("--nonce", required=True, help="Número de secuencia")
    sign_parser.add_argument("--gas", help="Límite de gas (opcional)")
    sign_parser.add_argument("--data", help="Datos hex (opcional)")
    
    # Comando recv
    recv_parser = subparsers.add_parser("recv", help="Verificar transacciones recibidas")
    recv_parser.add_argument("--path", default="inbox/", help="Ruta a archivo o directorio")
    
    # Comandos adicionales
    subparsers.add_parser("list", help="Listar transacciones")
    subparsers.add_parser("status", help="Mostrar estado del wallet")
    
    args = parser.parse_args()
    wallet = ColdWalletCLI()
    
    if args.command == "init":
        wallet.init()
    elif args.command == "address":
        wallet.address()
    elif args.command == "sign":
        wallet.sign(args)
    elif args.command == "recv":
        wallet.recv(args)
    elif args.command == "list":
        wallet.list()
    elif args.command == "status":
        wallet.status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

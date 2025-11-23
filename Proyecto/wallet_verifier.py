
import json
import base64
import hashlib
from datetime import datetime
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed_module
from cryptography.exceptions import InvalidSignature


# reading the tx file
def load_signed_file(tx_location):
    try:

        with open(tx_location ,'r') as tx_file:
           datos_tx = json.load(tx_file)      #diccionario


           output_tx = datos_tx["tx"] # Muestra el diccionario tx
           output_pubkey_b64 = datos_tx["pubkey_b64"]
           output_signature_b64 = datos_tx["signature_b64"]
           pubkey_bytes = base64.b64decode(output_pubkey_b64) # De base_64 a bytes
           signature_bytes = base64.b64decode(output_signature_b64)
           #print(output_tx)  # Muestra de la salida de tx
           #processed_output = print(json.dumps(datos_tx, indent=2))# muestra en terminal, ELIMINAR DESPUÉS

    except FileNotFoundError:
        print(f"ERROR: No se encontró el archivo '{tx_location}' en la ruta\n")
        return None
    
    except json.JSONDecodeError:
        print(f"ERROR: El archivo '{tx_location}' no es un JSON válido.\n")
        return None
    
    return output_tx, pubkey_bytes, signature_bytes

def canonical_signed_json(data: dict) -> bytes:
    """
    - Claves ordenadas
    - Sin espacios
    - UTF-8
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")



def verify_signature(pubkey_bytes, signature_bytes, canonical_tx):
    pb_Key = ed_module.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        pb_Key.verify(signature_bytes, canonical_tx)
        print("Valid signature")
        return True
    except InvalidSignature:
        print("Signature NOT valid")
        return False
    except ValueError:
        print("Error with the public key")
        return False




def derived_address_from_pubkey(pubkey_bytes, tx_from_address):
    """
    Address = RIPEMD-160(SHA-256(pubkey)), hex string.
    """
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new("ripemd160", sha).digest()

    return ripe.hex() == tx_from_address


        

    





if __name__ == "__main__":

    sig_tx = input("\nEnter signed transaction path: ")
    tx_dict, pubkey_bytes, signature_bytes = load_signed_file(sig_tx)

    canonical_tx = canonical_signed_json(tx_dict)
    #print(f"\n{canonical_tx}\n")  # Verificación
    #print(pubkey_bytes)            #Verificación
    
    if verify_signature(pubkey_bytes, signature_bytes, canonical_tx) == False:
        print("Invalid transaction.\n")
        exit()   

    if derived_address_from_pubkey(pubkey_bytes, tx_dict["from"]) == False:
        print("The address does not match\n")
        exit()
    else:
        print("Address verified\n")



       
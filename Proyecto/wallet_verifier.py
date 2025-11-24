
import json
import base64
import hashlib
from datetime import datetime
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed_module
from cryptography.exceptions import InvalidSignature


#pubkey_b64 y sig_scheme
  
def safe_b64decode(label, b64_string):
    try:
        return base64.b64decode(b64_string)
    except:
        print(f"Error decoding Base64 for {label}")
        return None
    
def check_length(label, byte_string, expected_len):
        if len(byte_string) != expected_len:
            print(f"Invalid {label} length")
            return False
        return True

    #Nonce y Value
def ensure_int(label, value):
    try:
        int(value)
        return True
    except:
        print(f"{label} is not a valid number")
        return False
    



# reading the tx file
def load_signed_file(tx_location):
    try:

        with open(tx_location ,'r') as tx_file:
           data_tx = json.load(tx_file)      #diccionario

           #Verificar que los datos existen en signed_tx.json
           required_data_tx = [ "tx", "pubkey_b64", "sig_scheme", "signature_b64"]
           for required_data in required_data_tx:
               if required_data not in data_tx:
                print("Missing field:", required_data)
                return None
               

           #Verifica que sig_scheme sea el adecuado   
           if data_tx["sig_scheme"] != "Ed25519":
               print("Unsupported signature scheme:", data_tx["sig_scheme"])
               return None
               
            
            #Verificar que tx es diccionario
           if not isinstance(data_tx["tx"], dict):
                print("Invalid tx structure")
                return None
           
            #Verifica que existan los datos en "tx"
           required_tx_fields = ["from", "to", "value", "nonce", "timestamp"]
           for required_tx in required_tx_fields:
               if required_tx not in data_tx["tx"]:
                   print("Missing tx field:", required_tx)
                   return None
           #Verifica formato de timestamp
           try:
               datetime.fromisoformat(data_tx["tx"]["timestamp"].replace("Z",""))
           except:
               print("Invalid timestamp format")
               return None
               
           #Verifica que nonce sea número
           if not ensure_int("nonce", data_tx["tx"]["nonce"]):
               return None
           
           #Verifica que value sea número
           if not ensure_int("value", data_tx["tx"]["value"]):
               return None
            
           


           output_tx = data_tx["tx"] # Muestra el diccionario tx
           output_pubkey_b64 = data_tx["pubkey_b64"]
           output_signature_b64 = data_tx["signature_b64"]
 
            #Verifica b64
           pubkey_bytes = safe_b64decode("public key", output_pubkey_b64)
           if pubkey_bytes is None:
               return None

           signature_bytes = safe_b64decode("signature", output_signature_b64)
           if signature_bytes is None:
               return None
           #Verifica longitud
           if not check_length("public key", pubkey_bytes, 32):
                return None

           if not check_length("signature", signature_bytes, 64):
                return None
           #print(output_tx)  # Muestra de la salida de tx
           #processed_output = print(json.dumps(data_tx, indent=2))# muestra en terminal, ELIMINAR DESPUÉS

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


        
def check_source_sequence(origin_address, sequence_string):

    sequence_int = int(sequence_string)
    
    if origin_address not in nonce_tracker:
        nonce_tracker[origin_address] = sequence_int
        return True
    else:
        print("Repeated Nonce")

    last_seen = nonce_tracker[origin_address]

    if sequence_int > last_seen: #Verificar Nonce actual
        nonce_tracker[origin_address] = sequence_int
        return True
    else:
        print("Old nonce")
    return False
    





if __name__ == "__main__":

    nonce_tracker = {}

    sig_tx = input("\nEnter signed transaction path: ").strip()

    result = load_signed_file(sig_tx)

    if result is None:
        print("Transaction rejected.\n")
        exit()

    tx_dict, pubkey_bytes, signature_bytes = result

    canonical_tx = canonical_signed_json(tx_dict)
    #print(f"\n{canonical_tx}\n")  # Verificación
    #print(pubkey_bytes)            #Verificación
  
    if verify_signature(pubkey_bytes, signature_bytes, canonical_tx) == False:
        print("Invalid transaction\n")
        exit()   

    if derived_address_from_pubkey(pubkey_bytes, tx_dict["from"]) == False:
        print("The address does not match\n")
        exit()
    else:
        print("Address verified\n")

    if check_source_sequence(tx_dict["from"], tx_dict["nonce"]) == False:
        print("Invalid nonce\n")
        exit()


    print("Transaction accepted \n")








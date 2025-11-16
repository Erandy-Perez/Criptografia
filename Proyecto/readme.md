build_run_instructions:
    - paso: "Instalar dependencias"
      comandos:
        - "pip install cryptography==42.0.7"
        - "pip install argon2-cffi==23.1.0"

    - paso: "Ejecutar el script"
      comando: "python wallet_A.py"
      resultado: "Genera el archivo keystore_A.json con todos los campos requeridos por la Parte A."

  generated_fields:
    - "Llave privada cifrada (AES-256-GCM)"
    - "Llave pública en Base64"
    - "Parámetros de Argon2id"
    - "Nonce y etiqueta de autenticación (GCM Tag)"
    - "Dirección derivada (SHA-256 → RIPEMD-160)"
    - "Checksum del archivo"

  library_versions:
    python: "3.11+"
    cryptography: "42.0.7"
    argon2-cffi: "23.1.0"

  threat_model_summary:
    offline_bruteforce:
      descripcion: "Argon2id mitiga ataques de fuerza bruta mediante alto costo de memoria y tiempo."
    keystore_theft:
      descripcion: "La llave privada solo se almacena en forma cifrada usando AES-256-GCM."
    tampering_protection:
      descripcion: "La etiqueta GCM detecta cualquier modificación en el ciphertext o en el nonce."
    checksum_protection:
      descripcion: "El checksum detecta corrupción o alteración no autorizada del archivo keystore."
    memory_attacks:
      descripcion: "Argon2id es memory-hard y dificulta ataques en GPU o ASIC."

  known_limitations:
    - "La dirección se deriva al estilo Bitcoin (SHA-256 → RIPEMD-160), no Ethereum."
    - "No implementa firmado de transacciones (Parte B)."
    - "No verifica firmas (Parte C)."
    - "No simula operaciones ni balances del wallet (Parte D)."
    - "La seguridad depende completamente de la fortaleza de la passphrase utilizada."
    - "No se realiza borrado seguro de material criptográfico en memoria."
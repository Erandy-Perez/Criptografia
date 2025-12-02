# Cold Wallet - Proyecto Criptografía 2026-1

Implementación de una billetera fría (cold wallet) criptográfica con funcionalidades completas de gestión de claves, firma y verificación de transacciones.

# Instalación

```bash
# Clonar repositorio
git clone <repo-url>
cd cold-wallet

# Instalar dependencias
pip install -r requirements.txt

# Instalar como comando global (opcional)
pip install -e .

```
# Uso
```bash
# Crear nuevo keystore
wallet init

# Mostrar dirección pública
wallet address

# Firmar transacción
wallet sign --to <dirección> --value <monto> --nonce <secuencia>

# Verificar transacciones recibidas
wallet recv --path inbox/

# Listar transacciones
wallet list

# Estado del wallet
wallet status
```
# Estructura de archivos

``` bash
cold-wallet/
├── main.py              # CLI principal
├── wallet_A.py          # Gestión de claves
├── wallet_transactions.py # Modelo y firma
├── wallet_verifier.py   # Verificación
├── keystore.json        # Keystore (generado)
├── inbox/              # Transacciones recibidas
├── outbox/             # Transacciones firmadas
├── verified/           # Transacciones verificadas
├── tests/              # Pruebas unitarias
└── README.md

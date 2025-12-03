from setuptools import setup

setup(
    name="cold-wallet",
    version="1.0.0",
    # Módulos .py que tienes en la carpeta Proyecto
    py_modules=["main", "wallet_A", "wallet_transactions", "wallet_verifier"],
    install_requires=[
        "cryptography>=42.0.0",
        "argon2-cffi>=23.1.0",
    ],
    entry_points={
        "console_scripts": [
            # nombre_del_comando = modulo:funcion
            "wallet=main:main",
        ],
    },
)

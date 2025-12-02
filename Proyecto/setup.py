from setuptools import setup, find_packages

setup(
    name="cold-wallet",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=42.0.0",
        "argon2-cffi>=23.1.0",
    ],
    entry_points={
        "console_scripts": [
            "wallet=main:main",
        ],
    },
)

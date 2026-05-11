from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def build_legacy_ec_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key


def use_legacy_ecdh():
    exchange = ec.ECDH()
    return exchange


def use_legacy_ecdsa():
    signature_algorithm = ec.ECDSA(hashes.SHA256())
    return signature_algorithm

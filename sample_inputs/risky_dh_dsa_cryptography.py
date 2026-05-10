from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, dsa


def build_legacy_dh_parameters():
    parameters = dh.generate_parameters(
        generator=2,
        key_size=2048,
        backend=default_backend(),
    )
    return parameters


def build_legacy_dsa_key():
    private_key = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend(),
    )
    return private_key

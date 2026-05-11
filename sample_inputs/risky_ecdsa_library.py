import ecdsa


def build_legacy_signing_key():
    return ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)

from Crypto.PublicKey import DSA, RSA


def build_pycryptodome_rsa_key():
    return RSA.generate(2048)


def build_pycryptodome_dsa_key():
    return DSA.generate(2048)

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

jwt_algorithm = "RS256"
ssh_host_key_algorithm = "ssh-rsa"
tls_signature_algorithm = "ecdsa-sha2-nistp256"
rsa_key_header = "-----BEGIN RSA PRIVATE KEY-----"

exchange_key = x25519.X25519PrivateKey.generate()
signing_key = ed25519.Ed25519PrivateKey.generate()

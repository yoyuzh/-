from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def payload() -> bytes:
    return b"demo-message"


if __name__ == "__main__":
    message = payload()

    # 演示：这里故意使用 RSA，便于扫描器识别
    private_key = None
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    print(signature[:8])

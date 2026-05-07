from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes


class CryptoEngine:
    SALT_SIZE = 16
    IV_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32
    ITERATIONS = 100000

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return PBKDF2(password, salt, dkLen=CryptoEngine.KEY_SIZE, count=CryptoEngine.ITERATIONS)

    @staticmethod
    def encrypt_file(input_file: str, output_file: str, password: str):
        salt = get_random_bytes(CryptoEngine.SALT_SIZE)
        key = CryptoEngine.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(CryptoEngine.IV_SIZE))
        
        with open(input_file, "rb") as f:
            data = f.read()

        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(output_file, "wb") as f:
            # Structure: Salt (16) + Nonce (12) + Tag (16) + Ciphertext
            f.write(salt)
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)

    @staticmethod
    def decrypt_file(input_file: str, output_file: str, password: str):
        with open(input_file, "rb") as f:
            salt = f.read(CryptoEngine.SALT_SIZE)
            nonce = f.read(CryptoEngine.IV_SIZE)
            tag = f.read(CryptoEngine.TAG_SIZE)
            ciphertext = f.read()

        key = CryptoEngine.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            with open(output_file, "wb") as f:
                f.write(plaintext)
            return True
        except ValueError:
            return False

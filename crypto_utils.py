import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# RSA Key Generation
def rsa_key_gen():
    private_key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    return private_key, public_key


# Convert public key to bytes so it can be sent to client
def serialize(public_key):
    serialized_public=public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_public


# Convert received PEM data back to public key object
def load_public_key(serialized_public):
    public_key=serialization.load_pem_public_key(serialized_public)
    return public_key


# RSA encryption
def rsa_encrypt(public_key, plaintext):
    ciphertext=public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# RSA decryption
def rsa_decrypt(private_key, ciphertext):
    plaintext=private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# Generate HMAC
def generate_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


# Verify HMAC
def verify_hmac(key, msg, shmac):
    rhmac=generate_hmac(key, msg)
    return hmac.compare_digest(rhmac, shmac)

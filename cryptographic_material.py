import os
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
from package.sphincs import Sphincs


def generate_key_pair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_sign_key_pair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(key, data):
    signature = key.sign(data)
    return signature


def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def sign_sphincs(key, data):
    sphincs = Sphincs()
    sphincs.set_winternitz(4)
    sphincs.set_hypertree_height(4)
    signature = sphincs.sign(data, key)
    print("Signature bytes-size: ", len(signature))
    return signature


def verify_sphincs(key, sig, m):
    try:
        sphincs.verify(m, sig, key)
        return True
    except InvalidSignature:
        return False


# input: key, output: bytes
def dh(key1, key2):
    shared_key = key1.exchange(key2)
    return shared_key


def message_encrypt(nonce, data, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESGCM(key)
    cipher_text = aesgcm.encrypt(nonce, data, add)
    return cipher_text


def message_decrypt(nonce, cipher_text, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce, cipher_text, add)
    return plain_text


# use aesgcm, aes
def encrpt_AEAD(nonce, data, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESGCM(key)
    cipher_text = aesgcm.encrypt(nonce, data, add)
    return cipher_text


def decrpt_AEAD(nonce, cipher_text, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce, cipher_text, add)
    return plain_text


def encrpt_AEAD_aes_ccm(nonce, data, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESCCM(key)
    cipher_text = aesgcm.encrypt(nonce, data, add)
    return cipher_text


def decrpt_AEAD_aes_ccm(nonce, cipher_text, add, key):
    nonce = nonce.to_bytes(12)
    aesgcm = AESCCM(key)
    plain_text = aesgcm.decrypt(nonce, cipher_text, add)
    return plain_text


def encode_bytes_pub(key_pub):
    key_bytes = key_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return key_bytes


def encode_bytes_priv(key_pub):
    key_bytes = key_pub.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return key_bytes


def decode_bytes_pub_x(bytes):
    return x25519.X25519PublicKey.from_public_bytes(bytes)


# signature test
# ik, ik_pub = generate_key_pair()
# ik_pub_bytes = ik_pub.public_bytes(
#     encoding=serialization.Encoding.Raw,
#     format=serialization.PublicFormat.Raw
# )
# spk,spk_pub,signature = generate_key_pair_signed(ik_pub_bytes)
#
# is_valid = verify_signature(spk_pub, ik_pub_bytes, signature)
# print(is_valid)

m = b"No one knows the reason for all this, but it is probably quantum. - Pyramids, Terry Pratchett (1989)"

sphincs = Sphincs()
sk, pk = sphincs.generate_key_pair()
print("Secret Key: ", sk)
print()
print("Public Key: ", pk)

sig = sign_sphincs(sk,m)

print("Is signature correct ? ", verify_sphincs(pk, sig, m))

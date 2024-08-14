# test
import random
import string
import timeit

import cryptographic_material
from group_message import *


# stateC = group.member_dict['C']

# print(stateA.__dict__)
# print(stateB.__dict__)

# Individual function running
# msg = (b'U%!1899JC|:50zRZD&V5l\\z_9?uB7ufN<sXbV`ziLA|z+AOCOC3<o#/@;7{U]iDx!%&PE>#Y2xZ~R[pi>0{'
#        b'GPM|+:D4213124123!ctB2!yc^')
# nonce = 1
# ad = b'ad'
# key = os.urandom(16)
#
# aes_gcm_siv_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD_aes_gcm_siv(nonce, msg, ad, key),
#                                      number=10000)
# print(f"AES_GCM_SIV encryption runtime: {aes_gcm_siv_enc_time} seconds")
#
# aes_gcm_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD(nonce, msg, ad, key), number=10000)
# print(f"AES_GCM encryption runtime: {aes_gcm_enc_time} seconds")
#
# aes_ccm_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD_aes_ccm(nonce, msg, ad, key), number=10000)
# print(f"AES_CCM encryption runtime: {aes_ccm_enc_time} seconds")
#
# aes_gcm_ct = cryptographic_material.encrpt_AEAD(nonce, msg, ad, key)
# aes_ccm_ct = cryptographic_material.encrpt_AEAD_aes_ccm(nonce, msg, ad, key)
# aes_gcm_siv_ct = cryptographic_material.encrpt_AEAD_aes_gcm_siv(nonce, msg, ad, key)
#
# aes_gcm_siv_dec_time = timeit.timeit(
#     lambda: cryptographic_material.decrpt_AEAD_aes_gcm_siv(nonce, aes_gcm_siv_ct, ad, key), number=10000)
# print(f"AES_GCM_SIV decryption runtime: {aes_gcm_siv_dec_time} seconds")
#
# aes_gcm_dec_time = timeit.timeit(lambda: cryptographic_material.decrpt_AEAD(nonce, aes_gcm_ct, ad, key), number=10000)
# print(f"AES_GCM decryption runtime: {aes_gcm_dec_time} seconds")
#
# aes_ccm_dec_time = timeit.timeit(lambda: cryptographic_material.decrpt_AEAD_aes_ccm(nonce, aes_ccm_ct, ad, key),
#                                  number=10000)
# print(f"AES_CCM decryption runtime: {aes_ccm_dec_time} seconds")

# signature test

# m = b"No one knows the reason for all this, but it is probably quantum. - Pyramids, Terry Pratchett (1989)"
#
# sphincs = Sphincs()
# sk_sph, pk_sph = sphincs.generate_key_pair()
# # generate_sign_key_pair()  return ed25519 keys
# sk_ed, pk_ed = generate_sign_key_pair()
#
# # ed25519_sign_time = timeit.timeit(lambda: cryptographic_material.sign_data(sk_ed,m), number=10000)
# # print(f"Ed25519 signing runtime: {ed25519_sign_time} seconds")
# #
# # sphincs_sign_time = timeit.timeit(lambda: cryptographic_material.sign_sphincs(sk_sph,m), number=10)
# # print(f"Sphincs signing runtime: {sphincs_sign_time} seconds")
#
# sig_ed = cryptographic_material.sign_data(sk_ed,m)
# sig_sph = cryptographic_material.sign_sphincs(sk_sph,m)
#
# ed25519_verify_time = timeit.timeit(lambda: cryptographic_material.verify_signature(pk_ed,m,sig_ed), number=10000)
# print(f"Ed25519 verify runtime: {ed25519_verify_time} seconds")
#
# sphincs_verify_time = timeit.timeit(lambda: cryptographic_material.verify_sphincs(pk_sph,m,sig_sph), number=10)
# print(f"Sphincs verify runtime: {sphincs_verify_time} seconds")

# encrypt_test('AES-GCM')

# Group Creation Test
def group_creation_test(group_size, enc_mode, sign_mode):
    group_id = [str(i) for i in range(group_size)]
    test_group = Group(group_id)
    test_group.group_creation(enc_mode, sign_mode)


test_cases = [
    # {'enc_mode': 'AES-GCM', 'sign_mode': 'ed25519', 'group_size': 300, 'label': 'AES-GCM with ed25519'},
    {'enc_mode': 'AES-GCM-SIV', 'sign_mode': 'ed25519', 'group_size': 10, 'label': 'AES-GCM-SIV with ed25519'},
    # {'enc_mode': 'AES-CCM', 'sign_mode': 'ed25519', 'group_size': 100, 'label': 'AES-CCM with ed25519'},
    # {'enc_mode': 'AES-GCM', 'sign_mode': 'sphincs', 'group_size': 10, 'label': 'AES-GCM with sphincs'},
]


# Iterate through each test case and execute the timeit function
for case in test_cases:
    enc_mode = case['enc_mode']
    sign_mode = case['sign_mode']
    group_size = case['group_size']
    label = case['label']

    group_creation_time = timeit.timeit(lambda: group_creation_test(group_size, enc_mode, sign_mode), number=1)
    print(f"10-people group creation time {label}: {group_creation_time} seconds")


# def group_message_test(test_group, group_size, enc_mode, sign_mode):
#     sender_id = str(random.randint(0, group_size - 1))
#     characters = string.ascii_letters + string.digits + string.punctuation
#     random_string = ''.join(random.choice(characters) for _ in range(100))
#     test_group.message_send(sender_id, random_string, enc_mode, sign_mode)
#
#
# group_size = 10
# group_id = [str(i) for i in range(group_size)]
# test_group = Group(group_id)
# test_group.group_creation('AES-GCM', 'ed25519')
#
# # Iterate through each test case and execute the timeit function
# for case in test_cases:
#     enc_mode = case['enc_mode']
#     sign_mode = case['sign_mode']
#     # group_size = case['group_size']
#     label = case['label']
#
#     message_sending_10_time = timeit.timeit(lambda: group_message_test(test_group, group_size, enc_mode, sign_mode),
#                                             number=200)
#     print(f"10-people group creation time {label}: {message_sending_10_time} seconds")

#
# message_sending_10_time = timeit.timeit(lambda: group_message_test(test_group, group_size, enc_mode, sign_mode), number=200)
# print(f"10-people group creation time aes-gcm: {message_sending_10_time} seconds")

# test
import string
import timeit
import random

import cryptographic_material
from group_message import *
from concurrent.futures import ThreadPoolExecutor

group = Group(['A', 'B'])
group.group_creation()
stateA = group.member_dict['A']
stateB = group.member_dict['B']
# stateC = group.member_dict['C']

# print(stateA.__dict__)
# print(stateB.__dict__)

# Individual function running
msg = (b'U%!1899JC|:50zRZD&V5l\\z_9?uB7ufN<sXbV`ziLA|z+AOCOC3<o#/@;7{U]iDx!%&PE>#Y2xZ~R[pi>0{'
       b'GPM|+:D4213124123!ctB2!yc^')
nonce = 1
ad = b'ad'
key = os.urandom(32)

aes_gcm_siv_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD_aes_gcm_siv(nonce, msg, ad, key), number=10000)
print(f"AES_GCM_SIV encryption runtime: {aes_gcm_siv_enc_time} seconds")

aes_gcm_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD(nonce, msg, ad, key), number=10000)
print(f"AES_GCM encryption runtime: {aes_gcm_enc_time} seconds")

aes_ccm_enc_time = timeit.timeit(lambda: cryptographic_material.encrpt_AEAD_aes_ccm(nonce, msg, ad, key), number=10000)
print(f"AES_CCM encryption runtime: {aes_ccm_enc_time} seconds")


aes_gcm_ct = cryptographic_material.encrpt_AEAD(nonce, msg, ad, key)
aes_ccm_ct = cryptographic_material.encrpt_AEAD_aes_ccm(nonce, msg, ad, key)
aes_gcm_siv_ct = cryptographic_material.encrpt_AEAD_aes_gcm_siv(nonce, msg, ad, key)


aes_gcm_siv_dec_time = timeit.timeit(lambda: cryptographic_material.decrpt_AEAD_aes_gcm_siv(nonce, aes_gcm_siv_ct, ad, key), number=10000)
print(f"AES_GCM_SIV decryption runtime: {aes_gcm_siv_dec_time} seconds")

aes_gcm_dec_time = timeit.timeit(lambda: cryptographic_material.decrpt_AEAD(nonce, aes_gcm_ct, ad, key), number=10000)
print(f"AES_GCM decryption runtime: {aes_gcm_dec_time} seconds")

aes_ccm_dec_time = timeit.timeit(lambda: cryptographic_material.decrpt_AEAD_aes_ccm(nonce, aes_ccm_ct, ad, key), number=10000)
print(f"AES_CCM decryption runtime: {aes_ccm_dec_time} seconds")




# encrypt_test('AES-GCM')

# for i in range(100):
#     characters = string.ascii_letters + string.digits + string.punctuation
#     random_string = ''.join(random.choice(characters) for _ in range(100))
#
#     group.message_send('A', random_string, 'AES-GCM-IV')

# def send_single_message():
#     characters = string.ascii_letters + string.digits + string.punctuation
#     random_string = ''.join(random.choice(characters) for _ in range(100))
#     group.message_send('A', random_string, 'AES-GCM-IV')
#
# num_threads = 10
#
# # Using ThreadPoolExecutor to run the function in multiple threads
# with ThreadPoolExecutor(max_workers=num_threads) as executor:
#     futures = [executor.submit(send_single_message) for _ in range(100)]

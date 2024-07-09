# test
from group_message import *
from state import State

stateA = State('A')
stateB = State('B')
stateC = State('C')

# stateA.prekey_bundle_initial()
# stateB.prekey_bundle_initial()
# stateC.prekey_bundle_initial()


stateA.retrieve_keys()
stateB.retrieve_keys()
stateC.retrieve_keys()


two_party_channel_init(stateA,stateB)
print(stateA.__dict__)
# two_party_channel_init(stateA,stateC)
print(stateB.__dict__)


# print()
# two_party_channel_init(stateA,stateC)
# # make sure the first one is the caller
# group = [stateA, stateB, stateC]
# group = group_creation(group)
# #
# print(group[0].__dict__)
# print(group[1].__dict__)
# print(group[2].__dict__)

msg = 'this is first msg'

stateA, m = two_party_channel_send(stateA,msg)
stateB, m2 = two_party_channel_receiver(stateB,m)
print(stateA.__dict__)
print(stateB.__dict__)
print(m2)


# stateA, m = two_party_channel_send(stateA, msg)
#
# stateB, plain_text = two_party_channel_receive(stateB, m)

# print(plain_text)

# stateA = State('A')
# stateB = State('B')
#
# stateA, stateB, acc = two_party_channel_init(stateA, stateB, stateA.id, stateB.id)
#



# aesgcm_rk = AESGCM(encode_bytes_priv(stateA.dhs))
# aesgcm_sk = AESGCM(encode_bytes_pub(stateB.dhr['A']))
#
# message = b"test message"
# associated_data = b"associated data"
#
# # Encrypt the message using the first key (rk)
# nonce = os.urandom(12)  # GCM mode requires a 96-bit nonce
# ciphertext = aesgcm_rk.encrypt(nonce, message, associated_data)
#
# # Decrypt the message using the second key (sk)
# try:
#     decrypted_message = aesgcm_sk.decrypt(nonce, ciphertext, associated_data)
#     print("Decryption successful. Decrypted message:", decrypted_message)
#     if decrypted_message == message:
#         print("The keys are symmetric.")
#     else:
#         print("The keys are not symmetric.")
# except Exception as e:
#     print("Decryption failed:", e)
#     print("The keys are not symmetric.")

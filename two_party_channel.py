import os

from cryptographic_material import *
from transmission import *

"""
build x3dh channel between A and B, including the sk_ab generation and a(sender) send its ck and to b, b store the keys. 

args: state of both

return:new state
"""
def two_party_channel_init(state_a, state_b):
    id_a = state_a.id
    id_b = state_b.id
    state_a, initial_msg = two_party_channel_init_key_generate(state_a, id_b)
    state_b, response_msg = handle_initial_message(id_a, state_b, initial_msg)
    state_a = ratchet_initial_response_receiver(state_a, id_b, response_msg)
    return state_a, state_b


def pre_key_bundle_generation(id, sign_key, sign_key_pub, opk_num=20):
    ik, ik_pub = generate_key_pair()
    spk, spk_pub = generate_key_pair()

    ik_pub_bytes = encode_bytes_pub(ik_pub)
    spk_pub_bytes = encode_bytes_pub(spk_pub)
    data_to_sign = ik_pub_bytes + spk_pub_bytes

    prekey_signature = sign_data(sign_key, data_to_sign)

    opks = []
    for i in range(opk_num):
        opk, opk_pub = generate_key_pair()
        opks.append((opk, opk_pub))
    # store the prekey bundle

    pre_key_store(id, ik_pub, spk_pub, sign_key_pub, prekey_signature, opks)
    print(id, 'prekey_bundle generate successfully')
    return ik, ik_pub, spk, spk_pub, prekey_signature, opks


# Use prekey bundle to build channel by X3DH
def two_party_channel_init_key_generate(state, id_b):
    if state.ik_pub is None: return
    ik_pub_b, spk_pub_b, sign_key_pub, perkey_signature, opk_pub_b, opk_index = get_prekey_data(id_b)

    if not verify_signature(sign_key_pub, encode_bytes_pub(ik_pub_b) + encode_bytes_pub(spk_pub_b),
                            perkey_signature): raise Exception('Signature Verification Failure')
    ek, ek_pub = generate_key_pair()
    dh1 = dh(state.ik, spk_pub_b)
    dh2 = dh(ek, ik_pub_b)
    dh3 = dh(ek, spk_pub_b)
    # dh4 = dh(ek, opk_pub_b)
    info = (
            encode_bytes_pub(state.ik_pub) +
            b" | " +
            encode_bytes_pub(ik_pub_b) +
            b" | " +
            encode_bytes_pub(ek_pub) +
            b" | " +
            encode_bytes_pub(spk_pub_b)
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    # concatenated_dh = dh1 + dh2 + dh3 + dh4
    concatenated_dh = dh1 + dh2 + dh3
    sk = hkdf.derive(concatenated_dh)
    # use sk to distribute ek_a, spk
    state.eks = os.urandom(32)
    state.dhs = state.eks
    cipher_text = encrpt_AEAD(state.nonce, state.eks, info, sk)
    state.sk[id_b] = sk
    # state = ratchet_initial_sender(state, id_b, sk, spk_pub_b)
    # request database delete keys
    # cipher_text = encrpt_AEAD(state.nonce, encode_bytes_pub(state.dhs_pub), info, sk)
    ad = info
    initial_message = (cipher_text, ad, state.nonce, opk_index)

    return state, initial_message

def handle_initial_message(id_a, state, initial_message):
    # extract info from initial message
    cipher_text = initial_message[0]
    ad = initial_message[1]
    nonce = initial_message[2]
    opk_index = initial_message[3]

    # Extract the individual keys from the combined bytes ad
    components = ad.split(b" | ")

    # Assign the split components to the respective variables
    ik_pub_bytes_a = components[0]
    ek_pub_bytes_a = components[2]

    # Convert the bytes back to key objects
    ik_pub_a = decode_bytes_pub_x(ik_pub_bytes_a)
    ek_pub_a = decode_bytes_pub_x(ek_pub_bytes_a)
    # opk = state.opks[opk_index][0]
    # ad verify

    # SK generate
    dh1 = dh(state.spk, ik_pub_a)
    dh2 = dh(state.ik, ek_pub_a)
    dh3 = dh(state.spk, ek_pub_a)
    # dh4 = dh(opk, ek_pub_a)
    info = (
            encode_bytes_pub(ik_pub_a) +
            b" | " +
            encode_bytes_pub(state.ik_pub) +
            b" | " +
            encode_bytes_pub(ek_pub_a) +
            b" | " +
            encode_bytes_pub(state.spk_pub)
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    # concatenated_dh = dh1 + dh2 + dh3 + dh4
    concatenated_dh = dh1 + dh2 + dh3
    sk = hkdf.derive(concatenated_dh)
    plain_text = decrpt_AEAD(nonce, cipher_text, ad, sk)
    state.ekr[id_a] = plain_text
    state.dhr[id_a] = plain_text
    # If the decryption is successful, store the sk
    state.sk[id_a] = sk

    #  Generate own ck_b, share it with the sender
    state.eks = os.urandom(32)
    state.dhs = state.eks
    info = (state.id + id_a).encode('utf-8')
    cipher_text = encrpt_AEAD(state.nonce, state.eks, info, sk)
    response_message = (cipher_text, info, state.nonce)

    # Do not use the double ratchet initialisation in signal
    # dh_pub_a = decode_bytes_pub_x(plain_text)
    # # delete opk_p
    # state = ratchet_initial_receiver(state, id_a, sk, dh_pub_a)

    return state, response_message

def ratchet_initial_response_receiver(state,id_b,response_msg):
    cipher_text = response_msg[0]
    info = response_msg[1]
    nonce = response_msg[2]

    plain_text = decrpt_AEAD(nonce,cipher_text,info,state.sk[id_b])
    state.ekr[id_b] = decode_bytes_pub_x(plain_text)
    state.dhr[id_b] = decode_bytes_pub_x(plain_text)

    return state


def two_party_channel_send(state, msg):
    state.eks, mk = hkdf_ck(state.eks)
    # dhs might be a version mark
    ad = state.dhs
    cipher_text = message_encrypt(state.ime, msg.encode('utf-8'), key=mk, add=ad )
    # should syn the ime with receiver to handle out-of-order message, but now neglect it
    m = (cipher_text, ad, state.id, state.ime)
    state.ime += 1
    #  signing required
    return state,m

def two_party_channel_receiver(state, m):
    cipher_text = m[0]
    id_sender = m[2]
    ime = m[3]
    # ime syn --now skip

    state.ekr[id_sender], mk = hkdf_ck(state.ekr[id_sender])
    plain_text = decrpt_AEAD(ime,cipher_text,state.dhr[id_sender],mk)

    return state, plain_text

"""

 functions for double ratchet initialize in signal way 


# def ratchet_initial_sender(state, id_b, sk, spk_pub_b):
#     if state.dhs is None:
#         state.dhs, state.dhs_pub = generate_key_pair()
#     state.dhr[id_b] = spk_pub_b
#     dh1 = dh(state.dhs, spk_pub_b)
#     state.rk[id_b], state.cks = hkdf_rk(sk, dh1)
#     return state

def ratchet_initial_receiver(state, id_a, sk, dh_pub_a):
    # initial value set
    state.dhs = state.spk
    state.dhs_pub = state.spk_pub
    state.rk[id_a] = sk
    state.dhr[id_a] = dh_pub_a
    sk = dh(state.dhs, state.dhr[id_a])
    state.rk[id_a], state.ckr[id_a] = hkdf_rk(state.rk[id_a], sk)
    # key update
    state.dhs, state.dhs_pub = generate_key_pair()
    new_sk = dh(state.dhs, state.dhr[id_a])
    state.rk[id_a], state.cks = hkdf_rk(state.rk[id_a], new_sk)
    return state

def two_party_channel_send(state, plaintext):
    state.cks, mk = hkdf_ck(state.cks)
    ad = encode_bytes_pub(state.dhs_pub)
    cipher_text = message_encrypt(state.ime, plaintext.encode('utf-8'), key=mk, add=ad, )
    # should syn the ime with receiver to handle out-of-order message, but now neglect it
    m = (cipher_text, ad, state.id, state.ime)
    state.ime += 1
    return state, m


def two_party_channel_receive(state, m):
    cipher_text = m[0]
    # ad is the dhs of sender
    ad = m[1]
    id_sender = m[2]
    ime = m[3]
    # if the dhs don't match, update the DH keys
    if encode_bytes_pub(state.dhr[id_sender]) != ad:
        print('key update')
        state = dh_update_receiver(state, id_sender, decode_bytes_pub_x(ad))
    state.ckr[id_sender], mk = hkdf_ck(state.ckr[id_sender])
    plain_text = message_decrypt(ime, cipher_text, ad, mk)
    return state, plain_text
    
def dh_update_receiver(state, id_b, dhs_pub_b):
    state.dhr[id_b] = dhs_pub_b
    sk = dh(state.dhs, state.dhr[id_b])
    state.rk[id_b], state.ckr[id_b] = hkdf_rk(state.rk[id_b], sk)
    return state


def dh_update_sender(state, id):
    state.dhs, state.dhs_pub = generate_key_pair()
    dh1 = dh(state.dhs, state.dhr[id])
    state.rk[id], state.cks = hkdf_rk(state.rk)
    return state

"""





# extra function
def hkdf_rk(rk, dh):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'',
    )
    s = hkdf.derive(rk + dh)
    return s[:32], s[32:]


def hkdf_ck(ck):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'',
    )
    s = hkdf.derive(ck)
    return s[:32], s[32:]

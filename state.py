import cryptographic_material
import group_message
from two_party_channel import *


class State:
    def __init__(self, id):
        self.id = id  # it should be a random unique string
        self.group = []
        self.ssk_sign, self.spk_sign = generate_sign_key_pair('ed25519')
        self.sign_key = {}
        self.ik = None
        self.ik_pub = None
        self.spk = None
        self.spk_pub = None
        self.prekey_signature = None
        self.opks = []
        self.sk = {}
        self.cks = None
        self.ckr = {}
        self.ep = 0
        self.ime = 0
        self.imer = {}
        self.ick = 0
        self.ickr = {}
        self.kc = 0
        self.kcr = {}
        self.mk = {}
        self.nonce = 0
        # root key list
        self.rk = []

    def prekey_bundle_initial(self):
        (self.ik, self.ik_pub,
         self.spk, self.spk_pub, self.prekey_signature,
         self.opks) = pre_key_bundle_generation(self.id, self.ssk_sign, self.spk_sign)
        store_state(self)

    def retrieve_keys(self):
        self.ik, self.ik_pub, self.spk, self.spk_pub, self.prekey_signature = retrieve_state(self.id)

    def message_encrypt(self, msg, enc_mode, sign_mode):
        if self.cks is None: return
        self.cks, mk = hkdf_ck(self.cks)
        ad = self.id.encode('utf-8')
        cipher_text = cryptographic_material.AEAD_encrypt(nonce=self.ime, data=msg.encode('utf-8'), enc_mode=enc_mode,
                                                          key=mk, add=ad)
        m = (cipher_text, self.id, self.ime, self.ick, self.ep, self.kc)
        #  sign_mode=sign_mode,
        sign_m = sign_data(self.ssk_sign, m[0], sign_mode)
        self.ime += 1
        self.ick += 1
        return m, sign_m

    # input: cipher text m and signature sig
    # output: (state code, plaintext)
    def message_decrypt(self, m, sig, dec_mode, sign_mode):
        # m parse and verify
        cipher_text = m[0]
        sender_id = m[1]
        sender_ime = m[2]
        sender_ick = m[3]
        sender_ep = m[4]
        sender_kc = m[5]
        # sign_mode
        if not verify_signature(self.sign_key[sender_id], cipher_text, sig, sign_mode):
            raise Exception('Signature Verification Failure')

        # Epoch check
        if sender_ep > self.ep:
            print('The message from future, can not handle the msg')
            return 0, None

        # root key check
        if sender_kc > self.kcr[sender_id]:
            # return state code 2, inform system to update rk and try to decrypt again
            return 2, None

        # get the same receive chain, then go forward to get ick syn and generate mk
        if sender_ick > self.ickr[sender_id]:
            while sender_ick > self.ickr[sender_id]:
                # mk dictionary capacity check
                if sender_id not in self.mk:
                    self.mk[sender_id] = []
                # extend kc
                while len(self.mk[sender_id]) <= sender_kc:
                    self.mk[sender_id].append([])
                # extend ime
                while len(self.mk[sender_id][sender_kc]) <= sender_ime:
                    self.mk[sender_id][sender_kc].append(None)
                self.mk_generate_with_save(sender_id)

            # when send_ick == self_ick, get mk for this message
            mk = self.mk_generate(sender_id)
        elif sender_ick == self.ickr[sender_id]:
            mk = self.mk_generate(sender_id)
        else:
            mk = self.mk[sender_id][sender_kc][sender_ime]
            del self.mk[sender_id][sender_kc][sender_ime]
        plain_text = cryptographic_material.AEAD_decrypt(sender_ime, cipher_text, sender_id.encode('utf-8'), mk,
                                                         dec_mode)
        return 1, plain_text

    def cks_update(self):
        new_cks = os.urandom(32)
        self.kc += 1
        self.ick = 1
        self.ime = 0
        self.cks = new_cks
        # share new keys
        self.nonce += 1
        ms = {}
        for id in self.group:
            m = two_party_key_encrypt(self, id, new_cks, enc_mode='AES-GCM')
            ms[id] = m
        return ms

    def ck_receive(self, m, id_sender):
        new_key = two_party_key_decrypt(self, id_sender, m, dec_mode='AES-GCM')
        self.ckr[id_sender] = new_key
        self.ickr[id_sender] = 1
        self.kcr[id_sender] += 1
        self.imer[id_sender] = 0

    def mk_generate(self, sender_id):
        self.ckr[sender_id], mk = hkdf_ck(self.ckr[sender_id])
        self.imer[sender_id] += 1
        self.ickr[sender_id] += 1
        return mk

    def mk_generate_with_save(self, sender_id):
        self.ckr[sender_id], mk = hkdf_ck(self.ckr[sender_id])
        self.mk[sender_id][self.kc][self.imer[sender_id]] = mk
        self.imer[sender_id] += 1
        self.ickr[sender_id] += 1
        return mk

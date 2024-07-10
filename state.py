from two_party_channel import *


class State:
    def __init__(self, id):
        self.id = id  # it should be a random unique string
        self.group = []
        self.ssk_sign, self.spk_sign = generate_sign_key_pair()
        self.ik = None
        self.ik_pub = None
        self.spk = None
        self.spk_pub = None
        self.prekey_signature = None
        self.opks = []
        self.sk = {}
        self.dhs = None
        self.dhs_pub = None
        self.dhr = {}
        self.cks = None
        self.ckr = {}
        self.ep = 0
        self.ime = 0
        self.ick = 0
        self.kc = {}
        self.nonce = 0
        self.rk = {}

    def prekey_bundle_initial(self):
        (self.ik, self.ik_pub,
         self.spk, self.spk_pub, self.prekey_signature,
         self.opks) = pre_key_bundle_generation(self.id, self.ssk_sign, self.spk_sign)
        store_state(self)

    def retrieve_keys(self):
        self.ik, self.ik_pub, self.spk, self.spk_pub, self.prekey_signature = retrieve_state(self.id)

    def message_encrypt(self, msg):
        if self.cks is None: return
        self.cks, mk = hkdf_ck(self.cks)
        ad = self.dhs
        cipher_text = message_encrypt(self.ime, msg.encode('utf-8'), key=mk, add=ad)
        m = (cipher_text, ad, self.id, self.ime)
        self.ime += 1
        return m

    def message_decrypt(self, m):
        cipher_text = m[0]
        id_sender = m[2]
        ime = m[3]
        # ime syn --now skip
        self.ckr[id_sender], mk = hkdf_ck(self.ckr[id_sender])
        plain_text = decrpt_AEAD(ime, cipher_text, self.dhr[id_sender], mk)

        return plain_text

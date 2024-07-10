from two_party_channel import *


class State:
    def __init__(self, id):
        self.id = id  # it should be a random unique string
        self.group = []
        self.ssk_sign, self.spk_sign = generate_sign_key_pair()
        self.sign_key = {}
        self.ik = None
        self.ik_pub = None
        self.spk = None
        self.spk_pub = None
        self.prekey_signature = None
        self.opks = []
        self.sk = {}
        self.dhr = {}
        self.cks = None
        self.ckr = {}
        self.ep = 0
        self.ime = 0
        self.ick = 0
        self.kc = {}
        self.nonce = 0

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
        m = (cipher_text, self.id, self.ime)
        sign_m = sign_data(self.ssk_sign, m[0])
        self.ime += 1
        return m, sign_m

    def message_decrypt(self, m, sig):
        cipher_text = m[0]
        id_sender = m[1]
        ime = m[2]
        if not verify_signature(self.sign_key[id_sender], cipher_text, sig):
            raise Exception('Signature Verification Failure')
        # ime syn --now skip
        self.ckr[id_sender], mk = hkdf_ck(self.ckr[id_sender])
        plain_text = decrpt_AEAD(ime, cipher_text, self.dhr[id_sender], mk)

        return plain_text

    def cks_update(self):
        new_cks = os.urandom(32)
        self.cks = new_cks

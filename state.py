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
        self.cks = None
        self.ckr = {}
        self.ep = 0
        self.ime = 0
        self.imer = {}
        self.ick = 0
        self.ickr = {}
        self.kc = 0;
        self.kcr = {}
        self.mk = {}
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
        ad = self.id.encode('utf-8')
        cipher_text = message_encrypt(self.ime, msg.encode('utf-8'), key=mk, add=ad)
        m = (cipher_text, self.id, self.ime, self.ick, self.ep, self.kc)
        sign_m = sign_data(self.ssk_sign, m[0])
        self.ime += 1
        self.ick += 1
        return m, sign_m

    def message_decrypt(self, m, sig):
        # m parse and verify
        cipher_text = m[0]
        sender_id = m[1]
        sender_ime = m[2]
        sender_ick = m[3]
        sender_ep = m[4]
        sender_kc = m[5]
        if not verify_signature(self.sign_key[sender_id], cipher_text, sig):
            raise Exception('Signature Verification Failure')

        # if e=ep, locate mk
        if sender_ep == self.ep:
            # go forward to get ick syn and generate mk
            if sender_ick >= self.ickr[sender_id]:
                step = sender_ick - self.ickr[sender_id]
                for i in range(step):
                    self.ckr[sender_id], mk = hkdf_ck(self.ckr[sender_id])
                    self.imer[sender_id] += 1;
                    # save mk in dict[sender][ck_index][mk_index]
                    self.mk[sender_id][self.kc][self.ime] = mk
                # when send_ick == self_ick, get mk for this message
                self.ckr[sender_id], mk = hkdf_ck(self.ckr[sender_id])
        elif sender_ep < self.ep:
            mk = self.mk[sender_id][sender_kc][sender_ime]
            # if key used, delete it
            del self.mk[sender_id][sender_kc][sender_ime]
        else:
            print('The message from future, can not handle the msg')
            return None

        plain_text = decrpt_AEAD(sender_ime, cipher_text, sender_id.encode('utf-8'), mk)

        return plain_text

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
            m = two_party_key_encrypt(self, id, new_cks)
            ms[id] = m
        return ms

    def ck_receive(self, m, id_sender):
        new_key = two_party_key_decrypt(self,id_sender,m)
        self.ckr[id_sender] = new_key
        self.ickr[id_sender] = 1
        self.kcr[id_sender] += 1
        self.imer[id_sender] = 0

from two_party_channel import *


class State:
    def __init__(self, id):
        self.id = id  #it should be a random unique string
        self.group = None
        self.ssk_sign, self.spk_sign = generate_sign_key_pair()
        self.ik = None
        self.ik_pub = None
        self.spk = None
        self.spk_pub = None
        self.prekey_signature =None
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
        self.nonce = 256
        self.rk = {}
        self.ek = None
        self.ekr = {}


    def prekey_bundle_initial(self):
        (self.ik, self.ik_pub,
         self.spk, self.spk_pub, self.prekey_signature,
         self.opks) = pre_key_bundle_generation(self.id, self.ssk_sign, self.spk_sign)
        store_state(self)

    def retrieve_keys(self):
        self.ik,self.ik_pub,self.spk,self.spk_pub,self.prekey_signature = retrieve_state(self.id)
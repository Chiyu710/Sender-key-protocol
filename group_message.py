#
import copy

from state import State
from two_party_channel import *
from itertools import combinations


# Group has variables for the entire group for group creation and message encryption
class Group:
    def __init__(self, ids):
        self.member_dict = {}
        self.member = ids
        for user_id in ids:
            state = State(user_id)
            if search_id(user_id):
                state.retrieve_keys()
            else:
                state.prekey_bundle_initial()
            self.member_dict[user_id] = state

    def group_creation(self):
        pairs = combinations(self.member, 2)
        # Perform double ratchet initialisation on each other
        for a, b in pairs:
            state_a = self.member_dict[a]
            state_b = self.member_dict[b]
            state_a, state_b = two_party_channel_init(state_a, state_b)
            self.member_dict[a] = state_a
            self.member_dict[b] = state_b
        for user in self.member_dict.values():
            user.group = copy.copy(self.member)
            user.group.remove(user.id)
            user.nonce += 1
            user.ep += 1
            self.member_dict[user.id] = user

    def group_add(self, id):
        if id in self.member:
            print("member already exist")
            return
        state = State(id)
        state.group = copy.copy(self.member)
        if search_id(id):
            state.retrieve_keys()
        else:
            state.prekey_bundle_initial()
        for user in self.member_dict.values():
            user, state = two_party_channel_init(user, state)
            user.group.append(id)
            user.nonce += 1
            self.member_dict[user.id] = user
        self.member.append(id)
        self.member_dict[id] = state

    def group_remove(self, id):
        if id not in self.member:
            print("member does not exist")
            return
        self.member.remove(id)
        self.member_dict.remove(id)
        # update ck to keep forward security
        for user in self.member_dict.values():
            user.ep += 1
            user.cks_update()
            # should inform other members to update ckr

    def group_key_update(self, ms, id_sender):
        for id in ms.keys():
            m = ms[id]
            self.member_dict[id].ck_receive(m, id_sender)

    def message_send(self, sender_id, m, enc_mode='AES-GCM', sign_mode='ed25519'):
        state_sender = self.member_dict[sender_id]
        c, sig = state_sender.message_encrypt(m, enc_mode, sign_mode)
        # may be need member check?
        for receiver in state_sender.group:
            self.message_receive(receiver, c, sig, dec_mode=enc_mode, sign_mode=sign_mode)
        return "acc"

    def message_receive(self, receiver_id, c, sig, dec_mode, sign_mode):
        state_receiver = self.member_dict[receiver_id]
        code, m = state_receiver.message_decrypt(c, sig, dec_mode, sign_mode)

        print(receiver_id, code, m)

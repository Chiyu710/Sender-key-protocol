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
            state =  State(user_id)
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




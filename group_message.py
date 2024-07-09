#
from two_party_channel import *


def group_creation(group_list):
    state_a = group_list[0]
    # creat the id list
    group_ids = []
    for s in group_list:
        group_ids.append(s.id)
    # if the group already exist, cancel creat
    if state_a.dhs is not None or state_a.ep != 0: return

    state_a.group = group_ids
    state_a.group.remove(state_a.id)

    for i, user_b in enumerate(group_list):
        if i == 0: continue
        user_b.group = group_ids
        user_b.group.remove(user_b.id)
        if user_b.id == state_a.id: continue
        state_a, user_b = two_party_channel_init(state_a, user_b)
        # Update the list
        group_list[i] = user_b
    group_list[0] = state_a
    return group_list

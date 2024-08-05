# test
import string

import random
from group_message import *
from state import State

group = Group(['A', 'B', 'C'])
group.group_creation()
stateA = group.member_dict['A']
stateB = group.member_dict['B']
# stateC = group.member_dict['C']

print(stateA.__dict__)
print(stateB.__dict__)

for i in range(10):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(random.choice(characters) for _ in range(100))

    group.message_send('A', random_string)
    group.message_send('B', random_string)



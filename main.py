# test
from group_message import *
from state import State

group = Group(['A','B','C'])
group.group_creation()
stateA = group.member_dict['A']
stateB = group.member_dict['B']
stateC = group.member_dict['C']


print(stateA.__dict__)
print(stateB.__dict__)
print(stateC.__dict__)

ms = stateA.cks_update()
m, sig = stateA.message_encrypt('test message')
group.group_key_update(ms,'A')
stateB = group.member_dict['B']
stateC = group.member_dict['C']

print(stateA.__dict__)
print(stateB.__dict__)
print(stateC.__dict__)

t1 = stateB.message_decrypt(m,sig)
t2 = stateC.message_decrypt(m,sig)

print(t1, t2)
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

m = stateA.message_encrypt('test message')

t1 = stateB.message_decrypt(m)
t2 = stateC.message_decrypt(m)

print(t1, t2)
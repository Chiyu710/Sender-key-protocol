# test
from group_message import *
from state import State

group = Group(['A','B','C'])
group.group_creation()
stateA = group.member_dict['A']
stateB = group.member_dict['B']
stateC = group.member_dict['C']


group.group_add('E')
stateD = group.member_dict['E']
m, sig = stateA.message_encrypt('test message')
print(stateA.__dict__)
print(stateB.__dict__)
print(stateC.__dict__)
print(stateD.__dict__)


t1 = stateB.message_decrypt(m,sig)
t2 = stateC.message_decrypt(m,sig)
t3 = stateD.message_decrypt(m,sig)
print(t1, t2,t3)
# COMPLETE THE SCRIPT TO GET THE FLAG
# USE PYTHON3
# YOU SHOULD MAKE USE OF THE PYTHON CRYPTO LIBRARY
# YOU MAY NEED TO INSTALL PYCRYPTODOME BEFORE YOU CAN RUN THE CORRECTED SCRIPT
# Hint: Look at the crypto libraries that are imported
# Hint 2: Based on Hint 1, what library do you need for the code to work? What library do you not need for the code to work?

import codecs
import hashlib
from Crypto.Cipher import AES

table = [b'J+TRKJnPo0EAaLH5oio7qW6lC92FUFY96kZPBFqj4NU=',
	b'UERMnI8D1rOakgIExgaBrSqxzgWkSl/PY58t5MuryL4=',
	b'CFXKWz5CUJJyPrQB1Axqo4K7xMEr6xKIxpCz9Q1+Lc8=',
	b'mSzAc6NvQHOiZyCcfa7m/E+CIuDAJHNrYdHqCWO9qs8=',
	b'r/81JVwz7QtfBjZoYoxhx1PFbc+32WmzAfEiROMfs+4=',
	b'mFcLrpE/mJu4kfrgIMjnAhzrYHjyjyUZCOrRbBXjzFw=',
	b'QZV3lswJ5cjD0vPOJD2RNsGmpmJfEidHHdyECpx/AGk=',
	b'H2wx879JqZVmousKnHip3iSMw6MvxeMqgxIY3ZseToY=',
	b'OUUHem3lwgSA2PqLDkp7XY8inlI1fYw0l0wYKVBJ7uA=',
	b'NTAl0vlCxoxlwZCddxSJS5c80ALp0I4DMPwJCb1qer4=',
	b'59meCW3BGFMrVoKS40Net4bogld8uNDLpWmouuTu8iU=',
	b'mEXv5c3fRSiJlfc+4/XAVKhhsnunCoPgmHw9raybrsw=',
	b'3fxahhfCY27tjTduqeW+f8qxtnRCQkabDzzwdixqFUc=',
	b'xbAbq0HnibOd2uKAvmazFvq+5SWzyvKG1gIB/uUqLu4=',
	b'hiw6A01RyDcOJTVSJ1/XxIQLZI40tgX5cOHlFsVFwTM=',
	b'Rq+xfITYIhhdsUpchEBJ7Dinn9wi42+mtjuQhWSY3YM=',
	b'BpUeSFVAnsoFwDiBfVuvRGOe3UKJrnl3Z2wlQ2WDigw=',
	b'+O1srpp/thvcvm7nhdbn4M6Xg0DiVCuxTezRtPX6M6A=',
	b'7BTnOYJA3NyCE+SGGeH6mq+WXbFM+QLd4DmIqVYhZ1w=',
	b'EynIrUqnKQX0rv9cqgEhwkxxUwCb2GLUgN4pTpmKESM=',
	b'GGDLLuW08z4YaXVke4FGf9CcsGa0x+fbclto0ZOT+7o=',
	b'er2/8Q4XeF05y3q4DtgxrC5tfpawfZR5qg55qlcLPA8=',
	b'VptI/j/Vnyrh/H8DH/lyRjgZqIvG1vxXvhV3xJk35No=',
	b'78BQJHX3w1Nayqoe05Af5IMfxpbQNjpPPYcpKUsSYus=',
	b'v9sGcgXR+x8gzRr4dVQXUjVNWsAsgG4VeOaRuaiJ9CU='
]

count = 0

key =  b'i want 16 bytezzi want 16 bytezz'
cipher = AES.new(key, ?)

while count < 25:
	string1 = table[count]
	count = count + 1
	rotten = codecs.encode(str(string1), 'rot-13')
	for i in range(999):
		rotten = cipher.decrypt(rotten)
		
	print(rotten)

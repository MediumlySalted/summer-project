from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS
'''
Source code: https://jhuisi.github.io/charm/_modules/abenc_maabe_rw15.html
'''

# ========== Global Setup =========== #
group = PairingGroup('SS512')
abe = DACMACS(group)

public_parameters, _ = abe.setup()
authorities = {}
users = {}

# ========= Authority Setup ========= #
aid1 = "aid1"
aid1_attrs = ['TOPSECRET', 'EMPLOYEE']
abe.setupAuthority(public_parameters, aid1, aid1_attrs, authorities)

aid2 = "aid2"
aid2_attrs = ['ENGINEER', 'RESEARCH']
abe.setupAuthority(public_parameters, aid2, aid2_attrs, authorities)

# =========== User Setup ============ #
uid = "user1"
user1 = {'id': 'user1', 'authoritySecretKeys': {}, 'keys': None}
user1['keys'], users[user1['id']] = abe.registerUser(public_parameters)

abe.keygen(public_parameters, authorities[aid1], 'TOPSECRET',
           users[user1['id']], user1['authoritySecretKeys'])
abe.keygen(public_parameters, authorities[aid2], 'ENGINEER',
           users[user1['id']], user1['authoritySecretKeys'])

# =========== Encryption ============ #
message = group.random(GT)
print(f"\nOriginal message: {message}")

policy = '(TOPSECRET or EMPLOYEE)'
ciphertext = abe.encrypt(public_parameters, policy, message, authorities[aid1])

# =========== Decryption ============ #
token = abe.generateTK(public_parameters, ciphertext,user1['authoritySecretKeys'], user1['keys'][0])
decrypted_message = abe.decrypt(ciphertext, token, user1['keys'][1])
print(f"\nDecrypted message: {decrypted_message}")

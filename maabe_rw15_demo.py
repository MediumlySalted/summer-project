from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15, merge_dicts
'''
Source code: https://jhuisi.github.io/charm/_modules/abenc_dacmacs_yj14.html
'''

# ========== Global Setup =========== #
group = PairingGroup('SS512')
maabe = MaabeRW15(group)

public_parameters = maabe.setup()

# ========= Authority Setup ========= #
pk1, sk1 = maabe.authsetup(public_parameters, 'AID1')
pk2, sk2 = maabe.authsetup(public_parameters, 'AID2')
public_keys = {'AID1': pk1, 'AID2': pk2}

# =========== User Setup ============ #
uid = "user1"
user_attributes1 = ['STUDENT@AID1', 'PHD@AID1']
user_attributes2 = ['STUDENT@AID2']

user_keys1 = maabe.multiple_attributes_keygen(public_parameters, sk1, uid, user_attributes1)
user_keys2 = maabe.multiple_attributes_keygen(public_parameters, sk2, uid, user_attributes2)
user_keys = {'GID': uid, 'keys': merge_dicts(user_keys1, user_keys2)} # Library uses gid instead of uid

# =========== Encryption ============ #
message = group.random(GT)
print(f"\nOriginal message: {message}")

policy = '(STUDENT@AID1 or PROFESSOR@AID2) and (STUDENT@AID1 or MASTERS@AID2)'
ciphertext = maabe.encrypt(public_parameters, public_keys, message, policy)

# =========== Decryption ============ #
decrypted_message = maabe.decrypt(public_parameters, user_keys, ciphertext)
print(f"\nDecrypted message: {decrypted_message}")

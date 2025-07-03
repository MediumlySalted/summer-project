
from charm.toolbox.pairinggroup import PairingGroup
from DACMACS import DACMACS

group = PairingGroup('SS512')
scheme = DACMACS(group)

SP, MSK, keys = scheme.setup()

print(f'System Parameter keys: {SP.keys()}')
print(f'Master Key: {MSK}')
print(f'Signature key, Verification key: {keys}')
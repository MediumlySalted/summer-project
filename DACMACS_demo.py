
from charm.toolbox.pairinggroup import PairingGroup
from DACMACS import DACMACS 

# ========== Global Setup =========== #
group = PairingGroup('SS512')
scheme = DACMACS(group)

SP, MSK, keys = scheme.setup()

print(f'\n\n{'=' * 32} Globals {'=' * 32}\n')
print(f'System Parameter keys: {SP.keys()}')
print(f'Master Key: {MSK}')
print(f'Signature key, Verification key: {keys}\n')

# ========= Authority Setup ========= #
scheme.attr_authority_setup(SP, scheme.attribute_authority_registration(["Auth1", "Company1"]))
scheme.attr_authority_setup(SP, scheme.attribute_authority_registration(["Auth2", "Company1"]))
scheme.attr_authority_setup(SP, scheme.attribute_authority_registration(["Auth3", "Company2"]))

print(f'\n{'=' * 32} Authorities {'=' * 32}\n')
for i, authority in enumerate(scheme.authorities):
    print(f'Authority {i}: {authority}')
    print(f'  info: {scheme.authorities[authority]['info']}')
    print(f'  public_key: {scheme.authorities[authority]['public_key']}')
    print(f'  secret_key: {scheme.authorities[authority]['secret_key']}')
    print(f'  attributes: {scheme.authorities[authority]['attributes']}')
    print()

# =========== User Setup ============ #
scheme.user_registration(SP, keys[0], ["Alice", "12/01/2001"])
scheme.user_registration(SP, keys[0], ["Bob", "01/31/1999"])

print(f'\n{'=' * 32} Users {'=' * 32}\n')
for i, user in enumerate(scheme.users):
    print(f'User {i}: {user}')
    print(f'  GPK: {scheme.users[user]['GPK']}')
    print(f'  GSK: {scheme.users[user]['GSK']}')
    print(f'  certificate: {scheme.users[user]['certificate']}')
    print()
print(f'{"=" * 32 * 3}\n')

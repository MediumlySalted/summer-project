"""
Code implementation of a DAC-MACS based cryptographic scheme written by
Kan Yang, Xiaohua Jia

Reference Paper:    "DAC-MACS: Effective Data Access Control for
                    Multi-Authority Cloud Storage Systems"

* Cryptographic Scheme: Multiauthority Ciphertext Polcity Access-Based Encryption
* Setting:              Pairing

Code Author:    Gabriel Adkins
Date:           Summer 2025
"""

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
import hashlib

class DACMACS:
    def __init__(self):
        self.group = PairingGroup('SS512')

    # ====== System Initialization ====== #
    def setup(self):
        """CASetup - Setup to be run by the certificate authority

        The CA setup algorithm takes no input other than the implicit
        security parameter. It outputs the master key, the system
        parameter, and signature and verification keys of the CA.

        Returns:
            MSK - master key (random number in Z_p)
            SP - system parameters
            (sk, vk) - signature and verification key of the CA
        """

        a = self.group.random(ZR)   # Random number ∈ Z_p
        g = self.group.random(G1)   # Generator of G (G1)
        g_a = g ** a                # Random element in G
        H = lambda x: self.group.hash(x, G1) # H: x → G1

        sk = self.group.random(ZR)  # Signature key
        vk = g ** sk                # Verification key

        # The paper defines SP as (g, g^a, G, G_T, H), but G and G_T
        # are defined in the library as G1 and GT, so I didn't include
        # them in the system parameter
        SP = { 'g': g, 'g_a': g_a, 'H': H}
        MSK = { 'a': a }
        return SP, MSK, (sk, vk)

    def user_registration(self, SP, signature_key, user_info):
        """UserReg - Used for users users to register to the CA

        The user registration algorithm takes the system parameter, the
        CA's signature key, and the user information (e.g., name,
        birthday etc.) as inputs. It authenticates the user and assigns
        a global unique user identity to the user. It outputs the user
        identity, a pair of global public/secret key, and a certificate
        which is signed by the CA.

        After registration, the CA sends the GPK, GSK pair and the user
        certificate to the user.

        Parameters:
            SP - system parameter
            signature_key - CA's signature key
            user_info - user information (e.g., name, birthday etc.)

        Returns:
            uid - global unique user identity
            (GPK, GSK) - public key, secret key
            certificate - certificate signed by the CA
        """
        g = SP['g']
        H = SP['H']

        u_uid = self.group.random(ZR)
        z_uid = self.group.random(ZR)
        g_inv_z = g ** (1 / z_uid)

        GPK = g ** u_uid    # global public key
        GSK = z_uid         # global secret key

        # Create uid from user_info
        uid = hashlib.sha256(str(user_info).encode()).hexdigest()

        # Create certificate item and signature
        item = uid + str(u_uid) + str(g_inv_z)
        hashed_item = H(item) # Ensures item ∈ G
        signature = hashed_item ** signature_key

        # Create certificate
        certificate = {
            'message': {
                'uid': uid,
                'u': u_uid,
                'g_inv_z': g_inv_z
            },
            'signature': signature
        }

        return uid, (GPK, GSK), certificate

    def attr_auth_registration(self, aa_info):
        """AAReg - Used for AAs to register to the CA

        The attribute authority registration algorithm takes the
        information of an attribute authority as input. It
        authenticates the AA and outputs a global authority identity
        aid for this AA.

        After registration, the CA should send its verification key and
        the system parameter to the attribute authority.

        Parameters:
            aa_info - attribute authority information

        Returns:
            aid - global authority identity
        """
        # Create attribute authority id
        aid = hashlib.sha256(str(aa_info).encode()).hexdigest()
        return aid

    def attr_auth_setup(self, SP, aid, attributes):
        """AASetup - Setup to be run by each attribute authority

        The attribute authority setup algorithm takes the system
        parameter and the global authority identity as inputs. It
        outputs a pair of secret/public authority keys, and the set of
        version keys and public attribute keys for each attribute.

        Parameters:
            SP - system parameter
            aid - attribute authority identifier

        Returns:
            sk - secret authority key
            pk - public authority key
            {vk's, pk's} - set of version keys and public attr keys
        """
        g = SP['g']
        H = SP['H']

        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        gamma = self.group.random(ZR)

        # Public authority key
        pk = {'e_gg_alpha': pair(g, g) ** alpha,
              'g_inv_beta': g ** (1 / beta),
              'g_gamma_beta': g ** (gamma / beta)}

        # Secret authority key
        sk = {'alpha': alpha,
              'beta': beta,
              'gamma': gamma}

        # Attribute public keys
        public_attr_keys = {}
        for attribute in attributes:
            vk = self.group.random(ZR)
            g_v = g ** vk
            public_attr_key = (g_v * H(attribute)) ** gamma

            public_attr_keys[attribute] = {
                'version_key': vk,
                'public_attr_key': public_attr_key
            }

        return sk, pk, public_attr_keys

    # ====== Secret Key Generation ====== #
    def verify_certificate(self, SP, certificate, verification_key):
        H = SP['H']
        msg = certificate['message']

        message_str = msg['uid'] + str(msg['u']) + str(msg['g_inv_z'])
        hashed = H(message_str)

        return pair(certificate['signature'], SP['g']) == pair(hashed, verification_key)

    def secret_key_gen(self, SP, auth_sk, public_attribute_keys,
                       attributes, user_certificate):
        """SKeyGen

        The secret key generation algorithm takes as
        inputs the secret authority key, the system
        parameter, the set of public attribute keys, a
        set of attributes that describes the secret key,
        and the certificate of user. It outputs a secret
        key for the user.

        Parameters: 
            auth_sk - secret authority key
            SP - system parameter
            public_attribute_keys - set of public attr keys
            attributes - set of attr describing the secret key
            user_certificate - certificate of the user

        Returns: 
            sk (uid) - secret key for the user
        """
        g_a = SP['g_a']
        t = self.group.random(ZR)

        # AA Variables
        alpha_k = auth_sk['alpha']
        beta_k = auth_sk['beta']
        gamma_k = auth_sk['gamma']

        # User Variables
        g_inv_z = user_certificate['message']['g_inv_z']
        u = user_certificate['message']['u']

        user_sk = {
            'K' : (g_inv_z ** alpha_k) * (g_a ** u) * (g_a ** (t / beta_k)),
            'L': g_inv_z ** (beta_k * t),
            'R': g_a ** t,
            'AK': {} # Attribute Keys
        }
        for attr in attributes:
            PAK = public_attribute_keys[attr]['public_attr_key']
            AK = (g_inv_z ** (beta_k * gamma_k * t)) * \
                (PAK ** (beta_k * u))
            user_sk['AK'][attr] = AK

        return user_sk

    # ========= Data Encryption ========= #
    def encrypt(self, SP, public_keys, public_attribute_keys, message, policy):
        """Encrypt

        The encryption algorithm takes as inputs the system parameter,
        a set of public keys from the involved authority set, a set of
        public attribute keys, the data, and an access structure over
        all the selected attributes from the involved AAs. The
        algorithm first encrypts the data by using symmetric encryption
        methods with a content key. Then, it encrypts the content key
        under the access structure and outputs a ciphertext. We will
        assume that the ciphertext implicitly contains the access
        structure.

        Parameters:
            SP - system parameter
            public_keys - set of public keys from the involved AAs
            public_attribute_keys - set of public attribute keys
            data - data to encrypt
            policy - access structure

        Returns:
            CT - ciphertext
        """
        util = SecretUtil(self.group, verbose=False)
        g = SP['g']
        g_a = SP['g_a']
        s = self.group.random(ZR)

        # C, C', and C'' (C0, C1, and C2)
        C1 = g ** s
        C2 = {}
        C0_product = self.group.init(GT, 1)
        for aid, pk in public_keys.items():
            C0_product *= pk['e_gg_alpha']
            C2[aid] = pk['g_inv_beta'] ** s

        C0 = message * C0_product ** s

        # C_i, D1_i, and D2_i
        C = {}
        D1 = {}
        D2 = {}
        shares = util.calculateSharesDict(s, util.createPolicy(policy))
        for attr, lambda_i in shares.items():
            aid = attr.split("@")[1].lower()

            PAK = public_attribute_keys[attr]['public_attr_key']
            pk = public_keys[aid]
            r = self.group.random(ZR)

            C[attr] = (g_a ** lambda_i) * (PAK ** -r)
            D1[attr] = pk['g_inv_beta'] ** r
            D2[attr] = pk['g_gamma_beta'] ** -r

        CT = {
            'policy': policy,
            'C0': C0, 'C1': C1, 'C2': C2,
            'C': C, 'D1': D1, 'D2': D2
        }

        return CT

    # ========= Data Decryption ========= #
    def token_gen(self, CT, GPK, secret_keys):
        """TKGen

        The decryption token generation algorithm takes as inputs the
        ciphertext which contains an access structure, user's global
        public key, and a set of user's secret keys. If the user holds
        sufficient attributes that satisfy the access structure, the
        algorithm can successfully compute the correct decryption token
        for the ciphertext.

        Parameters:
            CT - ciphertext
            GPK - user's global public key
            secret_keys - user's secret keys

        Returns:
            TK - decryption token for the ciphertext
        """
        util = SecretUtil(self.group, verbose=False)
        policy = util.createPolicy(CT['policy'])    # Parse the policy
        coefficients = util.getCoefficients(policy) # Calculate coefficients (ω_i)

        attributes = []
        for sk in secret_keys.values():
            attributes += list(sk['AK'].keys())

        pruned = util.prune(policy, attributes)
        if not pruned:
            raise Exception("Policy not satisfied by user's attributes")

        # Compute token pairing components
        TK = self.group.init(GT, 1)
        N_A = len(secret_keys)
        for aid, sk in secret_keys.items():
            dividend = (
                pair(CT['C1'], sk['K']) *           # e(C', K)
                pair(sk['R'], CT['C2'][aid]) ** -1  # e(R, C'')
            )
            divisor = self.group.init(GT, 1)

            for attr in pruned:
                attr_str = attr.getAttribute()
                
                # Only iterate attributes for this AA
                if attr_str.split("@")[1] != aid.upper(): continue

                w = coefficients[attr_str]
                divisor *= (
                    pair(CT['C'][attr_str], GPK) *                  # e(C_i, GPK)
                    pair(CT['D1'][attr_str], sk['AK'][attr_str]) *  # e(D1_i, K_p(i))
                    pair(CT['D2'][attr_str], sk['L'])               # e(D2_i, L_i)
                ) ** (w * N_A)

            TK *= dividend / divisor

        return TK

    def decrypt(self, CT, TK, GSK):
        """Decrypt

        The decryption algorithm takes as inputs the ciphertext, the
        decryption token, and the user's global secret key. It first
        decrypts the content key and further uses the content key to
        decrypt the data. It outputs the data.

        Parameters:
            CT - ciphertext to decrypt
            TK - decryption token for CT
            GSK - user's global secret key

        Returns:
            data - decrypted data
        """
        K = CT['C0'] / TK ** GSK
        return K

    # ====== Attribute Revocation ======= #
    def update_key_gen(self, SP, ASK, certificate, old_vk):
        """UKeyGen

        The update key generation algorithm takes as inputs the secret
        authority key, a set of user's secret, and the previous version
        key of the revoked attribute. It outputs both the user's Key
        Update Key and the Ciphertext Update Key.

        Parameters:
            SP - system parameters
            ASK - secret authority key
            certificate - user's certificate which contains u
            old_vk - version key of the revoked attribute

        Returns:
            KUK - user's key update key
            CUK - ciphertext update key
        """
        new_vk = self.group.random(ZR)

        AUK = ASK['gamma'] * (old_vk - new_vk)
        KUK = SP['g'] ** (certificate['message']['u'] * ASK['beta'] * AUK)
        CUK = ASK['beta'] * AUK / ASK['gamma']

        return (KUK, CUK)

    def secret_key_update(self, secret_key, KUK, attribute):
        """SKUpdate

        The user's secret key update algorithm takes as inputs the
        current secret key and its key update key. It outputs a new
        secret key.

        Parameters:
            secret_key - user's secret key
            KUK - user's key update key
            attribute - revoked attribute

        Returns:
            AK' - Updated attribute key
        """
        secret_key['AK'][attribute] = secret_key['AK'][attribute] * KUK
        return secret_key

    def ciphertext_update(self, CT, CUK, attribute):
        """CTUpdate

        The ciphertext update algorithm takes as inputs the current
        ciphertext and the ciphertext update key. It outputs a new
        ciphertext.

        Parameters:
            CT - current ciphertext
            CUK - CT's update key
            attribute - revoked attribute

        Returns:
            CT - new ciphertext
        """
        CT['C'][attribute] = CT['C'][attribute] * (CT['D2'][attribute] ** CUK)
        return CT

def test_demo(debug=False):
    dacmacs = DACMACS()

    # ========== Global Setup =========== #
    SP, MSK, (sk_CA, vk_CA) = dacmacs.setup()

    secret_keys = {}

    # ===== Register Users and AAs ====== #
    user_info = { 'name': 'Alice', 'dob': '01-01-2000' }
    uid, (GPK, GSK), cert = dacmacs.user_registration(SP, sk_CA, user_info)
    secret_keys[uid] = {}

    aid1 = dacmacs.attr_auth_registration("GOV")
    aid2 = dacmacs.attr_auth_registration("UT")

    # ============ AA Setup ============= #
    sk1, pk1, attr_keys1 = dacmacs.attr_auth_setup(SP, aid1, [f'TOPSECRET@{aid1.upper()}'])
    sk2, pk2, attr_keys2 = dacmacs.attr_auth_setup(SP, aid2, [f'EMPLOYEE@{aid2.upper()}'])

    public_keys = { aid1: pk1, aid2: pk2 }
    public_attr_keys = { **attr_keys1, **attr_keys2 }

    secret_keys[uid][aid1] = dacmacs.secret_key_gen(SP, sk1, attr_keys1, [f'TOPSECRET@{aid1.upper()}'], cert)
    secret_keys[uid][aid2] = dacmacs.secret_key_gen(SP, sk2, attr_keys2, [f'EMPLOYEE@{aid2.upper()}'], cert)

    # if debug:
    #     # ======== Attribute Authority Info ======== #
    #     print(f"\n\n{"=" * 25} Attribute Authorities {"=" * 25}")
    #     for aid, aa in dacmacs.authorities.items():
    #         print(f"\nAuthority ID: {aid}")
    #         print(f"  Info: {aa['info']}")
            
    #         print("  Public Key:")
    #         for k, v in aa['public_key'].items():
    #             print(f"    {k}: {v}")
    #         print("  Secret Key:")
    #         for k, v in aa['secret_key'].items():
    #             print(f"    {k}: {v}")
    #         print("  Attributes:")
    #         for attr in aa['attributes']:
    #             print(f"    {attr}")
    #         print("  Attribute Public Keys:")
    #         for attr, keys in aa['public_attr_keys'].items():
    #             print(f"    {attr}:")
    #             for k, v in keys.items():
    #                 print(f"      {k}: {v}")

    #     # =============== User Info ================ #
    #     print(f"\n\n{"=" * 25} Users {"=" * 25}")
    #     for uid, user in dacmacs.users.items():
    #         print(f"\nUser ID: {uid}")
    #         print(f"  GPK: {user['GPK']}")
    #         print(f"  GSK: {user['GSK']}")
    #         print(f"  Certificate:")
    #         for k, v in user['certificate']['message'].items():
    #             print(f"    {k}: {v}")
    #         print(f"  Signature: {user['certificate']['signature']}")
    #         print(f"  Secret Keys: ")
    #         for aid, keys in secret_keys.items():
    #             print(f"    {aid}: ")
    #             for k, v in keys.items():
    #                 print(f"      {k}: {v}")

    # ============= Encrypt ============= #
    data = dacmacs.group.random(GT)
    policy = f'TOPSECRET@{aid1.upper()} and EMPLOYEE@{aid2.upper()}'

    ciphertext = dacmacs.encrypt(SP, public_keys, public_attr_keys,
                                 data, policy)

    if debug:
        print(f"\n\n{"=" * 25} Encryption {"=" * 25}")
        print("\nPublic Keys: ")
        for aid, keys in public_keys.items():
            print(f"  AA: {aid}")
            for k, v in keys.items():
                print(f"    {k}: {v}")
        print("\nPublic Attribute Keys: ")
        for aid, keys in public_keys.items():
            print(f"  AA: {aid}")
            for k, v in keys.items():
                print(f"    {k}: {v}")
        print(f"\nCiphertext:")
        print(f"  Policy: {ciphertext['policy']}")
        print(f"  C0: {ciphertext['C0']}")
        print(f"  C1: {ciphertext['C1']}")
        print("  C2:")
        for aid, C2 in ciphertext['C2'].items():
            print(f"    {aid}: {C2}")
        print("  C:")
        for attr, C in ciphertext['C'].items():
            print(f"    {attr}: {C}")
        print("  D1:")
        for attr, D1 in ciphertext['D1'].items():
            print(f"    {attr}: {D1}")
        print("  D2:")
        for attr, D2 in ciphertext['D2'].items():
            print(f"    {attr}: {D2}")

    # ====== Attribute Revocation ======= #
    #   Comment out secret_key_update to test for decryption failure
    #   Leaving it in should lead to successful decryption
    KUK, CUK = dacmacs.update_key_gen(SP, sk1, cert, attr_keys1[f'TOPSECRET@{aid1.upper()}']['version_key'])
    secret_keys[uid][aid1] = dacmacs.secret_key_update(
        secret_keys[uid][aid1], KUK,
        f'TOPSECRET@{aid1.upper()}'
    )
    ciphertext = dacmacs.ciphertext_update(ciphertext, CUK, f'TOPSECRET@{aid1.upper()}')

    # ============= Decrypt ============= #
    token = dacmacs.token_gen(ciphertext, GPK, secret_keys[uid])
    content_key = dacmacs.decrypt(ciphertext, token, GSK)

    if debug:    
        print(f"\n\n{"=" * 25} Decrpytion {"=" * 25}")
        print(f"\nToken: {token}")
        print(f"\nConent Key: {content_key}")
        print()

    print(f'\n\n{'-' * 50}')
    if content_key == data: print("\nSuccessfully Decrypted!\n")
    else: print("\nDecryption Failed!\n")
    print(f'{'-' * 50}\n')

if __name__ == '__main__':
    test_demo(True)

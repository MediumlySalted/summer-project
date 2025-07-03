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
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import hashlib

class DACMACS:
    def __init__(self, group):
        self.group = group
        self.authorities = {}   # set of attribute authorities
        self.users = {}         # set of users

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

        # Store user data
        self.users[uid] = {
            'GPK': GPK,
            'GSK': GSK,
            'certificate': certificate
        }

        return uid, (GPK, GSK), certificate

    def attribute_authority_registration(self, aa_info):
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
        # Create & Store attribute authority id
        aid = hashlib.sha256(str(aa_info).encode()).hexdigest()
        self.authorities[aid] = {
            'info': aa_info,
            'public_key': None,
            'secret_key': None,
            'attributes': {}
        }

        return aid

    def attr_authority_setup(self, SP, aid):
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

        # Private authority key
        pk = {'e_g_alpha': pair(g, g) ** alpha,
              'g_inv_beta': g ** (1 / beta),
              'g_gamma_beta': g ** (gamma / beta)}
        
        # Secret authority key
        sk = {'alpha': alpha,
              'beta': beta,
              'gamma': gamma}
        
        # Attribute public keys
        public_attr_keys = {}
        for attribute in self.authorities[aid]["attributes"]:
            vk = self.group.random(ZR)
            g_v = g ** vk
            public_attr_key = (g_v * H(attribute)) ** gamma

            public_attr_keys[attribute] = {
                'version_key': vk,
                'public_attr_key': public_attr_key
            }

        # Store in authority registry
        self.authorities[aid]['public_key'] = pk
        self.authorities[aid]['secret_key'] = sk
        self.authorities[aid]['public_attr_keys'] = public_attr_keys

        return sk, pk, public_attr_keys


    # ====== Secret Key Generation ====== #
    def secret_key_gen(self, secret_authority_key, SP, public_attribute_keys,
                       attributes, user_certificate):
        """SKeyGen

        The secret key generation algorithm takes as
        inputs the secret authority key, the system
        parameter, the set of public attribute keys, a
        set of attributes that describes the secret key,
        and the certificate of user. It outputs a secret
        key for the user.

        Parameters: 
            secret_authority_key - secret authority key
            SP - system parameter
            public_attribute_keys - set of public attr keys
            attributes - set of attr describing the secret key
            user_certificate - certificate of the user

        Returns: 
            sk (uid) - secret key for the user
        """
        pass


    # ========= Data Encryption ========= #
    def encrypt(self, SP, public_keys, public_attribute_keys, data, policy):
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
        pass


    # ========= Data Decryption ========= #
    def token_gen(self, CT, public_keys, secret_keys):
        """TKGen

        The decryption token generation algorithm takes as inputs the
        ciphertext which contains an access structure, user's global
        public key, and a set of user's secret keys. If the user holds
        sufficient attributes that satisfy the access structure, the
        algorithm can successfully compute the correct decryption token
        for the ciphertext.

        Parameters:
            CT - ciphertext
            public_keys - user's global public key
            secret_keys - set of user's secret keys

        Returns:
            TK - decryption token for the ciphertext
        """
        pass

    def decrypt(self, CT, TK, secret_key):
        """Decrypt

        The decryption algorithm takes as inputs the ciphertext, the
        decryption token, and the user's global secret key. It first
        decrypts the content key and further uses the content key to
        decrypt the data. It outputs the data.

        Parameters:
            CT - ciphertext to decrypt
            TK - decryption token for CT
            secret_key - user's global secret key

        Returns:
            data - decrypted data
        """
        pass


    # ====== Attribute Revocation ======= #
    def user_key_gen(self, secret_authority_key, secrets, version_key):
        """UKeyGen

        The update key generation algorithm takes as inputs the secret
        authority key, a set of user's secret, and the previous version
        key of the revoked attribute. It outputs both the user's Key
        Update Key and the Ciphertext Update Key.

        Parameters:
            secret_authority_key - secret authority key
            secrets - set of user's secrets
            version_key - version key of the revoked attribute

        Returns:
            KUK - user's key update key
            CUK - ciphertext update key
        """
        pass

    def secret_key_update(self, secret_key, KUK):
        """SKUpdate

        The user's secret key update algorithm takes as inputs the
        current secret key and its key update key. It outputs a new
        secret key.

        Parameters:
            secret_key - secret key
            KUK - sk's key update key
        """
        pass

    def ciphertext_update(self, CT, CUK):
        """CTUpdate

        The ciphertext update algorithm takes as inputs the current
        ciphertext and the ciphertext update key. It outputs a new
        ciphertext.

        Parameters:
            CT - current ciphertext
            CUK - CT's update key

        Returns:
            CT - new ciphertext
        """
        pass


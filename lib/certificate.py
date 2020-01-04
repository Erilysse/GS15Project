import hashlib
import os
import textwrap
from datetime import datetime
import secrets
import dsa

import yaml

import crypto_utils as cu
import diffie_hellman
import dsa


""" Implementation of basics certificate system based on the X509 standard
Using explanations from https://www.commentcamarche.net/contents/198-les-certificats
Certificate_data : 
    X.509 version
    certificate serial number
    cipher algorithm used to sign the certificate's data 
    certifier's name (DN: Distinguished Name) 
    certificate beginning validity
    certificate end of validity
    Usage of the public key
    the public key of the futur certificate owner 
+ The certifier signature (thumbprint)
"""


class Certificate(object):
    """ Generate a certificate object based on a X509 one."""

    def __init__(self):
        """ class constructor
        :param public_key: owner's public key and other parameters
        """
        self.owner_pub_key = []
        self.data = {}  # init
        self.thumbprint = ''  # init
        self.signed_owner_public_key = ''
        pass

    def create_certificate(self, s_pubkey, c_pubkey):
        self.data = {
            'version_number': 3,
            'serial_number': hex(secrets.randbits(70)).zfill(20),  # Generating
            'signature_algorithm_ID': "sha256andDSA_encryption",
            'validity_period': [
                {'not_before': datetime.now()},
                {'not_after': datetime.now().replace(datetime.now().year + 1)}
            ],
            'subject_name': "C=FR, L=Troyes, O=GS15",
            'subject_public_key_info': [
                {'Public_key_algorithm': "DSA_PublicKey,"},
                {'Certifier_public_key': c_pubkey},
            ],
        }
        self.owner_pub_key = s_pubkey
        pass

    def __repr__(self):
        return "%s(owner_public_key=%r, data=%r, thumbprint=%r, signed_owner_public_key=%r)" % (
            self.__class__.__name__, self.owner_pub_key, self.data, self.thumbprint, self.signed_owner_public_key)

    def add_thumbprint(self):
        # Signing the certificate with sha 256 protocol. format = bytes
        self.thumbprint = '0x' + hashlib.sha256(str(self.owner_pub_key).encode('utf-8')).hexdigest()
        pass

    def add_signed_owner_pubkey(self, DSA_object):
        self.signed_owner_public_key = DSA_object.r
        pass


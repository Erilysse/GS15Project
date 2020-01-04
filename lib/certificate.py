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


def integrity_check(self):
    data_hash = '0x' + hashlib.sha3_256(str(self.data).encode('utf-8')).hexdigest()
    if self.data_hash == data_hash:
        print("\033[1;32m[+]\033[1;m \x1b[0mCERTIFICATE INTEGRITY CHECK SUCCESSFUL")
    else:
        raise ValueError("\033[1;31m[-] CERTIFICATE INTEGRITY ERROR \033[1;m \x1b[0m")
    pass


def certif_signature_check(certificate, n, e):
    """ RSA Signature Verification process
        :param n: <int> - public key (part I)
        :param e: <int> - public key (part II)
        :return:
        """

    if certificate.signed_owner_public_key is None:
        raise ValueError("\033[1;31m[-]\033[1;m \x1b[0mThe public key hasn't been signed\x1b[0m")

    decrypt = RSA().decrypt(self.subject_public_key[3], e, n)
    if self.subject_public_key[0] == decrypt:
        print("\033[1;32m[+]\x1b[0m Signature successfully verified")
    else:
        raise ValueError("\033[1;31m[-] \x1b[0mAn Error occure during the Signature Verification")
    pass


#########################
#                       #
#     UTT FUNCTIONS     #
#                       #
#########################

def UTT_Keys():
    """ UTT keys uses for signing certificates
    :return:
    """
    n = 1377509098008480396127958303819748433992949105181377053140915891376695195883290778221218088933434962641973110015445353418542569309002067115686248571002867189875217936404182802544731910461799455768010892400854168964736401754570445438641929199621147242389260768483864796511842511995505453651626335564527176888448927257182162891637497794363979001504448653142166088741568698662999277614491789821278421843862664666539304146276411982745178033236600257029151419927641556768990923858522467633561139237526453872497837105060069739337300261981819229092271970867556634847421738664731446368101923316045696830444511280987189062459
    e = 65537
    d = 190104536932384774139483328179466785346433742493751083466332205922708083970374344929151578579404802166948834910580214214779563729118958695512829015677181321983404925855739984399893613747528040308433015187138952518448485369626507068828248602254809744629593497116931125197237584871802936899036184018392145679034415203329144901072654601882084269449563972156700365310051854683440509827884157816995816274520217554951745117281220104019495384335953066813768105976095544280101713101181787149951134738704579538572139893603098294271329250298914673572078731179141664342050434426309395830527141022637844333071775999920254211017
    return n, e, d


def certifier_signature(certificate, ):
    """ UTT is a trusted third party
    This function allows it to "sign" a certificate (adding it's signature to the public key)
    :type certificate: Certificate
    """
    n, e, d = UTT_Keys()
    certificate.signing_public_key(d, n)
    assert len(certificate.subject_public_key) == 4
    print("\033[1;32m[+]\x1b[0m Certificate Successfuly Signed by UTT")
    pass


# TEST ZONE
if __name__ == "__main__":
    """
    # Process Certificate :
    # 1) WebSite create its certificate (with pub_s) and sent it to the certifier
    # 2) The certifier sign the certificate with DSA and its priv_c. The result is a signature sign
    #    |-> Su est ajouté à sa clé publique d'alice : (A, g, p, Su)
    # 4) WebSite send its pub_s (certificate) to the visitor
    # 6) The visitor take the pub_c from the certifier
    # 8) The visitor decipher the signature with certifier's pub_c. He verifies thant pub_c is pub_s. 
    """
    a = diffie_hellman.DH_gen_keys(640, 512)
    write_yaml(a, "aliceKeys" + ".yml")
    # Alice do things
    alice_keys = read_yaml("../tests/" + "aliceKeys" + ".yml")  # Alice is getting her certificate
    alice_cert = Certificate(a)

    # UTT's job
    UTT_Signature(alice_cert)

    # Bob's part
    utt_n, utt_e = UTT_Keys()[:2]
    wrap_n = textwrap.fill(hex(utt_n), 94, initial_indent="\t", subsequent_indent="\t\t")
    print("\033[1;97m[~]\x1b[0m UTT Public Keys:\n\tn:{0}\n\te:\t{1}".format(wrap_n, hex(utt_e)))
    alice_cert.pk_signature_check(utt_n, utt_e)

    pass

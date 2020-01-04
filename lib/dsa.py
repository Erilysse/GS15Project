from crypto_utils import *
import diffie_hellman
import hashlib
import random
import inspect

"""
def main():
    print("Starting the main function : DSA signature.")

    msg = "fnvopnpfaejiddffnjnjqmdknm"

    print("Generate Diffie_Hellman keys.")
    DH_params, alice_pub_key, alice_priv_key = diffie_hellman.DH_gen_keys(128, 64)  # CAN CHANGE SIZE OF p AND q
    aliceKeys = Key(DH_params, alice_pub_key, alice_priv_key)
    print("Proceeding to the message signature.")
    sign = DSA_sign(aliceKeys, msg)

    print("Signature Verification.")
    verif = DSA_verify(sign)
    assert verif
"""


def DSA_encrypt(key, msg):
    """
    @brief      Sign the message with the DSA method

    @param      key         The key we use to sign. key is a Key Object
    @param      msg         The message to sign

    @return     The signature is an object DSASignature
    """
    print("--   --   --   --   --   --   --   --   --   --   --")
    print("Starting the DSA signature function.")
    r = s = X = 0

    h = bytes2int(hashlib.sha256(msg).digest())
    print("Generate s and r")
    while s == 0:
        while r == 0:
            k = random.randint(1, key.param.q - 1)
            X = pow(key.param.g, k, key.param.p)
            r = X % key.param.q
        k_inv = inv(k, key.param.q)
        if k_inv is None:
            continue
        s = (k_inv * (h + key.private_key * r)) % key.param.q
    print("--   --   --   --   --   --   --   --   --   --   --")
    return DSASignature(key.param, key.public_key, r, s, msg.decode())


def DSA_decrypt(DSA_sig):
    """
    @brief      Verify the signature

    @param      DSA_sig  The DSA signature. It's an object DSASignature
    @param      msg      The message

    @return     The final state (useful to verify)
    """
    print("--   --   --   --   --   --   --   --   --   --   --")
    print("DSA_verify: starting function")

    if not (1 <= DSA_sig.r < DSA_sig.param.q and 1 <= DSA_sig.s < DSA_sig.param.q):
        return False

    h = bytes2int(hashlib.sha256(DSA_sig.msg.encode('utf-8')).digest())
    # h = bytes2int(DSA_sig.msg.encode('utf-8'))
    inv_s = inv(DSA_sig.s, DSA_sig.param.q)
    x = (h * inv_s) % DSA_sig.param.q
    w = (DSA_sig.r * inv_s) % DSA_sig.param.q
    X = (pow(DSA_sig.param.g, x, DSA_sig.param.p) * pow(DSA_sig.public_key, w, DSA_sig.param.p)) % DSA_sig.param.p
    v = X % DSA_sig.param.q
    print("--   --   --   --   --   --   --   --   --   --   --")
    return v == DSA_sig.r

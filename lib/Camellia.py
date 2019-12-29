from lib import crypto_utils as cu
import os

"""
    &           bitwise AND operation.
    |           bitwise OR operation. 
    ^           bitwise exclusive-OR operation.
    bytes_rol() logical left shift operation. 
    >>          logical right shift operation.
    <<<         left rotation operation.
    ~y          bitwise complement of y.
    0x          hexadecimal representation.
    
    Constant values : masks of different lengths and sigma, which represents "keys" in the F-function
    Hexadecimal notation.
"""
MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff
sigma = [
    0xA09E667F3BCC908B,
    0xB67AE8584CAA73B2,
    0xC6EF372FE94F82BE,
    0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D,
    0xB05688C2B3E6C1FD
]
"""
    Class CamelliaKey.
    Represents the key scheduling part.
"""


class CamelliaKey(object):
    """
    @brief   In this function, we initialize the object
    @:param  length         length of the camellia key
    @:param  ckey_adress    camellia private key file adress

    @:var   KL (key left block), KR (key right block)
    @:var   ckey (content of the file at the file adress ckey_adress)
    """

    def __init__(self, ckey_address):
        self.length = os.path.getsize(ckey_address)*4
        file = open(ckey_address, "r")
        ckey = int(file.read())
        file.close()
        if self.length == 128:
            self.KL = ckey
            self.KR = 0
        elif self.length == 192:
            self.KL = ckey >> 64
            self.KR = ((ckey & MASK64) << 64) | (~(ckey & MASK64))
        else:
            self.KL = ckey >> 128
            self.KR = ckey & MASK128
    """
        @brief      Generate KA
        @:return    ka
    """
    def generate_ka(self):
        temp1 = (self.KL ^ self.KR) >> 64
        temp2 = (self.KL ^ self.KR) & MASK64
        temp2 ^= f_function(temp1, sigma[0])
        temp1 ^= f_function(temp2, sigma[1])
        temp1 ^= (self.KL >> 64)
        temp2 ^= (self.KL & MASK64)
        temp2 ^= f_function(temp1, sigma[2])
        temp1 ^= f_function(temp2, sigma[3])
        ka = (temp1 << 64) | temp2
        return ka
    """
        @brief      Generate KB
        @:return    kb
    """
    def generate_kb(self):
        ka = self.generate_ka()
        temp1 = (ka ^ self.KR) >> 64
        temp2 = (ka ^ self.KR) & MASK64
        temp2 ^= f_function(temp1, sigma[4])
        temp1 ^= f_function(temp2, sigma[5])
        kb = (temp1 << 64) | temp2
        return kb

    """
        @brief      Generate all the subkeys for the encryption with a Camellia Key
        @:return    a table of subkeys
    """
    def generate_subkeys(self):
        ka = self.generate_ka()
        kb = self.generate_kb()
        if self.length == 128:
            k1 = ka >> 64
            k2 = ka & MASK64
            k3 = cu.bytes_rol(self.KL, 15) >> 64
            k4 = cu.bytes_rol(self.KL, 15) & MASK64
            k5 = cu.bytes_rol(ka, 15) >> 64
            k6 = cu.bytes_rol(ka, 15) & MASK64
            k7 = cu.bytes_rol(self.KL, 45) >> 64
            k8 = cu.bytes_rol(self.KL, 45) & MASK64
            k9 = cu.bytes_rol(ka, 45) >> 64
            k10 = cu.bytes_rol(self.KL, 60) & MASK64
            k11 = cu.bytes_rol(ka, 60) >> 64
            k12 = cu.bytes_rol(ka, 60) & MASK64
            k13 = cu.bytes_rol(self.KL, 94) >> 64
            k14 = cu.bytes_rol(self.KL, 94) & MASK64
            k15 = cu.bytes_rol(ka, 94) >> 64
            k16 = cu.bytes_rol(ka, 94) & MASK64
            k17 = cu.bytes_rol(self.KL, 111) >> 64
            k18 = cu.bytes_rol(self.KL, 111) & MASK64
            subk128 = [k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18]
            return subk128
        else:
            k1 = kb >> 64
            k2 = kb & MASK64
            k3 = cu.bytes_rol(self.KR, 15) >> 64
            k4 = cu.bytes_rol(self.KR, 15) & MASK64
            k5 = cu.bytes_rol(ka, 15) >> 64
            k6 = cu.bytes_rol(ka, 15) & MASK64
            k7 = cu.bytes_rol(kb, 30) >> 64
            k8 = cu.bytes_rol(kb, 30) & MASK64
            k9 = cu.bytes_rol(self.KL, 45) >> 64
            k10 = cu.bytes_rol(self.KL, 45) & MASK64
            k11 = cu.bytes_rol(ka, 45) >> 64
            k12 = cu.bytes_rol(ka, 45) & MASK64
            k13 = cu.bytes_rol(self.KR, 60) >> 64
            k14 = cu.bytes_rol(self.KR, 60) & MASK64
            k15 = cu.bytes_rol(kb, 60) >> 64
            k16 = cu.bytes_rol(kb, 60) & MASK64
            k17 = cu.bytes_rol(self.KL, 77) >> 64
            k18 = cu.bytes_rol(self.KL, 77) & MASK64
            k19 = cu.bytes_rol(self.KR, 94) >> 64
            k20 = cu.bytes_rol(self.KR, 94) & MASK64
            k21 = cu.bytes_rol(ka, 94) >> 64
            k22 = cu.bytes_rol(ka, 94) & MASK64
            k23 = cu.bytes_rol(self.KL, 111) >> 64
            k24 = cu.bytes_rol(self.KL, 111) & MASK64
            subk = [k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, k20, k21,
                    k22, k23, k24]
            return subk

    """
        @:brief     Generate_subkw aims to generate all the subkeys kw1, kw2, kw3 and kw4.
        @:return    a table of subkweys
    """

    def generate_subkw(self):
        if self.length == 128:
            k = self.generate_ka()
        else:
            k = self.generate_kb()
        kw1 = self.KL >> 64
        kw2 = self.KL & MASK64
        kw3 = cu.bytes_rol(k, 111) >> 64
        kw4 = cu.bytes_rol(k, 111) & MASK64
        subkweys = [kw1, kw2, kw3, kw4]
        return subkweys

    """
        @:brief     Generate_subke aims to generate all the subkeys ke1, ke2, ke3, etc... this subkeys are different if 
        the length of the key is 128 or if it is different
        @:return    a table of all the subkeys
    """

    def generate_subke(self):
        ka = self.generate_ka()
        if self.length == 128:
            ke1 = cu.bytes_rol(ka, 30) >> 64
            ke2 = cu.bytes_rol(ka, 30) & MASK64
            ke3 = cu.bytes_rol(self.KL, 77) >> 64
            ke4 = cu.bytes_rol(self.KL, 77) & MASK64
            subke128 = [ke1, ke2, ke3, ke4]
            return subke128
        else:
            ke1 = cu.bytes_rol(self.KR, 30) >> 64
            ke2 = cu.bytes_rol(self.KR, 30) & MASK64
            ke3 = cu.bytes_rol(self.KL, 60) >> 64
            ke4 = cu.bytes_rol(self.KL, 60) & MASK64
            ke5 = cu.bytes_rol(ka, 77) >> 64
            ke6 = cu.bytes_rol(ka, 77) >> MASK64
            subke = [ke1, ke2, ke3, ke4, ke5, ke6]
            return subke


"""
    Divide a 128 bits message in two parts
"""


def divide_message(message):
    mleft = message >> 64
    mright = message & MASK64
    return [mleft, mright]

"""
    @:param     subkw       the subkweys of a Camellia Key object
    @:return    invsubkw    the subkweys in a different order for the decryption
"""
def inverse_subkweys(subkw):
    invsubkw = [subkw[2], subkw[3], subkw[0], subkw[1]]
    return invsubkw


"""
    Encryption of a 128 bits message with camellia algorithm
    @:param chunk           a chunk of the message
    @:param camellia_key    Camellia Key object
"""


def encryption(chunk, camellia_key):
    subtext = divide_message(chunk)
    subk = camellia_key.generate_subkeys()
    subkw = camellia_key.generate_subkw()
    subke = camellia_key.generate_subke()
    data_for_cypher = feistel(subtext, subkw, subk, subke, camellia_key)
    # construction of the ciphertext  from temp1 and temp2
    ciphertext = (data_for_cypher[1] << 64) | data_for_cypher[0]
    return ciphertext


"""
    Decryption of a 128 bits cipher with camellia key
    @:param chunk_cipher    a chunk of the cipher message
    @:param camellia_key    Camellia Key object
"""


def decryption(chunk_cipher, camellia_key):
    subtext_cipher = divide_message(chunk_cipher)
    invsubkw = inverse_subkweys(camellia_key.generate_subkw())
    invsubk = camellia_key.generate_subkeys().reverse()
    invsubke = camellia_key.generate_subke().reverse()
    datafordecipher = feistel(subtext_cipher, invsubkw, invsubk, invsubke, camellia_key)
    plaintext = (datafordecipher[0] << 64) | datafordecipher[1]
    return plaintext


"""
    @:param subtext         string chunk of the message
    @:param subkw           string subkweys
    @:param subk            string subkeys
    @:param subke           string subkeeys
    @:param camellia_key    Camellia Key object
"""


def feistel(subtext, subkw, subk, subke, camellia_key):
    # Prewhitening of the left part and right part of the message
    temp1 = subtext[0] ^ subkw[0]
    temp2 = subtext[1] ^ subkw[1]
    # begin of first 6-round feistel
    temp2 ^= f_function(temp1, subk[0])
    temp1 ^= f_function(temp2, subk[1])
    temp2 ^= f_function(temp1, subk[2])
    temp1 ^= f_function(temp2, subk[3])
    temp2 ^= f_function(temp1, subk[4])
    temp1 ^= f_function(temp2, subk[5])
    # insertion of fl and flinv functions with ke1 and ke2
    temp1 = fl_function(temp1, subke[0])
    temp2 = flinv_function(temp2, subke[1])
    # continue with another 6-round feistel
    temp2 ^= f_function(temp1, subk[6])
    temp1 ^= f_function(temp2, subk[7])
    temp2 ^= f_function(temp1, subk[8])
    temp1 ^= f_function(temp2, subk[9])
    temp2 ^= f_function(temp1, subk[10])
    temp1 ^= f_function(temp2, subk[11])
    # new insertion of fl and flinv functions with ke3 and ke4
    temp1 = fl_function(temp1, subke[2])
    temp2 = flinv_function(temp2, subke[3])
    # last 6-round feistel for key 128bits
    temp2 ^= f_function(temp1, subk[12])
    temp1 ^= f_function(temp2, subk[13])
    temp2 ^= f_function(temp1, subk[14])
    temp1 ^= f_function(temp2, subk[15])
    temp2 ^= f_function(temp1, subk[16])
    temp1 ^= f_function(temp2, subk[17])
    if camellia_key.length != 128:
        temp1 = fl_function(temp1, subke[4])
        temp2 = flinv_function(temp2, subke[5])
        temp2 ^= f_function(temp1, subk[18])
        temp1 ^= f_function(temp2, subk[19])
        temp2 ^= f_function(temp1, subk[20])
        temp1 ^= f_function(temp2, subk[21])
        temp2 ^= f_function(temp1, subk[22])
        temp1 ^= f_function(temp2, subk[23])
    # postwhitening
    d2cipher = temp2 ^ subkw[2]
    d1cipher = temp1 ^ subkw[3]
    return [d1cipher, d2cipher]


"""
    round6feistel generalize the six round in feistel with the f_function and the subkeys
    @:param     temp1    temporary var
    @:param     temp2    temporary var
    @:param     subk     table of the subkeys used in this feistel's round
    @:param     firstknb number of the first subkey used in feistel's round
    
    @:return    tab      table of modified temp1 and temp2
"""


def round6feistel(temp1, temp2, subk, firstknb):
    temp2 ^= f_function(temp1, subk[firstknb])
    temp1 ^= f_function(temp2, subk[firstknb + 1])
    temp2 ^= f_function(temp1, subk[firstknb + 2])
    temp1 ^= f_function(temp2, subk[firstknb + 3])
    temp2 ^= f_function(temp1, subk[firstknb + 4])
    temp1 ^= f_function(temp2, subk[firstknb + 5])
    tab = [temp1, temp2]
    return tab


"""
    f_function
    @:param     inputdata
    @:param     subkey
    
    @:var       SBOX1[], SBOX2[], SBOX3[], SBOX4[]
    
    @:return    fout
"""


def f_function(inputdata, subkey):
    x = inputdata ^ subkey
    t1 = x >> 56
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >> 8) & MASK8
    t8 = x & MASK8
    t1 = SBOX1[t1]
    t2 = SBOX2[t2]
    t3 = SBOX3[t3]
    t4 = SBOX4[t4]
    t5 = SBOX2[t5]
    t6 = SBOX3[t6]
    t7 = SBOX4[t7]
    t8 = SBOX1[t8]
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    fout = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8
    return fout


"""
    fl_function takes two parameters :
    @:param     inputdata (64-bit)
    @:param     subkey (64-bit)

    @:var       x1, x2, k1, k2 (32-bit unsigned integer)

    @:return    data flout (64-bit)
"""


def fl_function(inputdata, subkey):
    x1 = inputdata >> 32
    x2 = inputdata & MASK32
    k1 = subkey >> 32
    k2 = subkey & MASK32
    x2 ^= cu.bytes_rol((x1 & k1), 1)
    x1 ^= (x2 | k2)
    flout = (x1 << 32) | x2
    return flout


"""
    flinv_function is the inverse function of the FL_function
    @:param     inputdata (64-bit)
    @:param     subkey (64-bit)

    @:var       y1, y2, k1, k2 (32-bit unsigned integer)

    @:return    data flout (64-bit)
"""


def flinv_function(inputdata, subkey):
    y1 = inputdata >> 32
    y2 = inputdata & MASK32
    k1 = subkey >> 32
    k2 = subkey & MASK32
    y1 ^= (y2 | k2)
    y2 ^= cu.bytes_rol((y1 & k1), 1)
    flinvout = (y1 << 32) | y2
    return flinvout

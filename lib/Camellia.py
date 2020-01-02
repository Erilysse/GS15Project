from lib import crypto_utils as cu
from bitstring import BitArray, Bits

"""
    &           bitwise AND operation.
    |           bitwise OR operation. 
    ^           bitwise exclusive-OR operation.
    <<          logical left shift operation. 
    >>          logical right shift operation.
    <<<         left rotation operation.
    ~y          bitwise complement of y.
    0x          hexadecimal representation of an integer.
    
    Constant values : masks of different lengths and sigma, which represents "keys" in the F-function
    Hexadecimal notation.
"""
MASK8  = BitArray("0x00000000000000ff")
MASK32 = BitArray("0x00000000ffffffff")
MASK64 = BitArray("0x0000000000000000ffffffffffffffff")
MASK128= BitArray("0xffffffffffffffffffffffffffffffff")

def re_64b(array):
    return array[-64:]


def re_64b_array(array_table):
    table_64b = []
    for a in array_table:
        table_64b.append(re_64b(a))
    return table_64b

def agg_128b(array):
    return BitArray("0x0000000000000000") + array


sigma = [
    BitArray("0xa09e667f3bcc908b"),
    BitArray("0xb67ae8584caa73b2"),
    BitArray("0xc6ef372fe94f82be"),
    BitArray("0x54ff53a5f1d36f1c"),
    BitArray("0x10e527fade682d1d"),
    BitArray("0xb05688c2b3e6c1fd")
]
SBOX1 = (
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158,
)


def SBOX2(x):
    return cu.int_rol(SBOX1[x], 1)


def SBOX3(x):
    return cu.int_rol(SBOX1[x], 7)


def SBOX4(x):
    return SBOX1[cu.int_rol(x, 1)]


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

    def __init__(self, ckey_address, length):
        self.length = length
        if self.length not in [128, 192, 256]:
            raise ValueError("Invalid key length, "
                             "it must be 128, 192 or 256 bits long!")
        # force bytes
        file = open(ckey_address, "r")
        ckey = file.read()
        file.close()
        ckey = "0x" + ckey
        # ckey is a 128bits BitArray Object
        ckey = BitArray(ckey)
        if self.length == 128:
            self.KL = ckey
            self.KR = BitArray(len(ckey))
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
        # mise en 64 bits car f_function n'autorise que les entrées de 64bits et les ^ n'est autorisée que sur des
        # bytearray de même taille
        temp1 = re_64b((self.KL ^ self.KR) >> 64)
        temp2 = re_64b((self.KL ^ self.KR) & MASK64)
        temp2 ^= f_function(temp1, sigma[0])
        temp1 ^= f_function(temp2, sigma[1])
        temp1 ^= re_64b((self.KL >> 64))
        temp2 ^= re_64b((self.KL & MASK64))
        temp2 ^= f_function(temp1, sigma[2])
        temp1 ^= f_function(temp2, sigma[3])
        # remise en 128 bits
        temp1 = agg_128b(temp1)
        temp2 = agg_128b(temp2)
        ka = (temp1 << 64) | temp2
        return ka

    """
        @brief      Generate KB
        @:return    kb
    """

    def generate_kb(self):
        if self.length != 128:
            ka = self.generate_ka()
            temp1 = re_64b((ka ^ self.KR) >> 64)
            temp2 = re_64b((ka ^ self.KR) & MASK64)
            temp2 ^= f_function(temp1, sigma[4])
            temp1 ^= f_function(temp2, sigma[5])
            temp1 = agg_128b(temp1)
            temp2 = agg_128b(temp2)
            kb = (temp1 << 64) | temp2
        else:
            kb = "0x00000000000000000000000000000000"
        return kb

    """
        @brief      Generate all the subkeys for the encryption with a Camellia Key
        @:return    a table of subkeys
    """

    def generate_subkeys(self):
        ka = self.generate_ka()
        if self.length == 128:
            k1 = ka >> 64
            k2 = ka & MASK64
            klc15 = self.KL.copy()
            klc15.rol(15)
            k3 = klc15 >> 64
            k4 = klc15 & MASK64
            kac15 = ka.copy()
            kac15.rol(15)
            k5 = kac15 >> 64
            k6 = kac15 & MASK64
            klc45 = self.KL.copy()
            klc45.rol(45)
            k7 = klc45 >> 64
            k8 = klc45 & MASK64
            kac45 = ka.copy()
            kac45.rol(45)
            k9 = kac45 >> 64
            klc60 = self.KL.copy()
            klc60.rol(60)
            k10 = klc60 & MASK64
            kac60 = ka.copy()
            kac60.rol(60)
            k11 = kac60 >> 64
            k12 = kac60 & MASK64
            klc94 = self.KL.copy()
            klc94.rol(94)
            k13 = klc94 >> 64
            k14 = klc94 & MASK64
            kac94 = ka.copy()
            kac94.rol(94)
            k15 = kac94 >> 64
            k16 = kac94 & MASK64
            klc111 = self.KL.copy()
            klc111.rol(111)
            k17 = klc111 >> 64
            k18 = klc111 & MASK64
            subk128 = [k1, k2, k3, k4, k5, k6, k7, k8,
                       k9, k10, k11, k12, k13, k14, k15,
                       k16, k17, k18]
            return re_64b_array(subk128)
        else:
            kb = self.generate_kb()
            k1 = kb >> 64
            k2 = kb & MASK64
            krc15 = self.KR.copy()
            krc15.rol(15)
            k3 = krc15 >> 64
            k4 = krc15 & MASK64
            kac15 = ka.copy()
            kac15.rol(15)
            k5 = kac15 >> 64
            k6 = kac15 & MASK64
            kbc30 = kb.copy()
            kbc30.rol(30)
            k7 = kbc30 >> 64
            k8 = kbc30 & MASK64
            klc45 = self.KL.copy()
            klc45.rol(45)
            k9 = klc45 >> 64
            k10 = klc45 & MASK64
            kac45 = ka.copy()
            kac45.rol(45)
            k11 = kac45 >> 64
            k12 = kac45 & MASK64
            krc60 = self.KR.copy()
            krc60.rol(60)
            k13 = krc60 >> 64
            k14 = krc60 & MASK64
            kbc60 = kb.copy()
            kbc60.rol(60)
            k15 = kbc60 >> 64
            k16 = kbc60 & MASK64
            klc77 = self.KL.copy()
            klc77.rol(77)
            k17 = klc77 >> 64
            k18 = klc77 & MASK64
            krc94 = self.KR.copy()
            krc94.rol(94)
            k19 = krc94 >> 64
            k20 = krc94 & MASK64
            kac94 = ka.copy()
            kac94.rol(94)
            k21 = kac94 >> 64
            k22 = kac94 & MASK64
            klc111 = self.KL.copy()
            klc111.rol(111)
            k23 = klc111 >> 64
            k24 = klc111 & MASK64
            subk = [k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18, k19, k20, k21,
                    k22, k23, k24]
            return re_64b_array(subk)

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
        kc = k.copy()
        kc.rol(111)
        kw3 = kc >> 64
        kw4 = kc & MASK64
        subkweys = [kw1, kw2, kw3, kw4]
        return re_64b_array(subkweys)

    """
        @:brief     Generate_subke aims to generate all the subkeys ke1, ke2, ke3, etc... this subkeys are different if 
        the length of the key is 128 or if it is different
        @:return    a table of all the subkeys
    """

    def generate_subke(self):
        ka = self.generate_ka()
        if self.length == 128:
            # make copy of ka to use rotation left
            kac = ka.copy()
            klc = self.KL.copy()
            # use rotation left, the result become the var
            kac.rol(30)
            klc.rol(77)
            ke1 = kac >> 64
            ke2 = kac & MASK64
            ke3 = klc >> 64
            ke4 = klc & MASK64
            subke128 = [ke1, ke2, ke3, ke4]
            return re_64b_array(subke128)
        else:
            krc = self.KR.copy()
            krc.rol(30)
            ke1 = krc >> 64
            ke2 = krc & MASK64
            klc = self.KL.copy()
            klc.rol(60)
            ke3 = klc >> 64
            ke4 = klc & MASK64
            kac = ka.copy()
            kac.rol(77)
            ke5 = kac >> 64
            ke6 = kac >> MASK64
            subke = [ke1, ke2, ke3, ke4, ke5, ke6]
            return re_64b_array(subke)


"""
    Divide a 128 bits BitArray Object in two 64bits BitArray object
"""


def divide_message(message):
    mleft = re_64b(message >> 64)
    mright = re_64b(message & MASK64)
    return [mleft, mright]


"""
    @:param     subkw       the subkweys of a Camellia Key object
    @:return    invsubkw    the subkweys in a different order for the decryption
"""


def inverse_subkweys(subkw):
    invsubkw = [subkw[2], subkw[3], subkw[0], subkw[1]]
    return invsubkw

def inverse_subk(subkeys):
    subkeys.reverse()
    return subkeys

def inverse_subke(subke):
    subke.reverse()
    return subke


"""
    Encryption of a 128 bits message with camellia algorithm
    @:param chunk           a chunk of the message (bytearray 128)
    @:param camellia_key    Camellia Key object
"""


def encryption(chunk, camellia_key):
    # chunk is divided into 2 64-bit BitArray Object
    subtext = divide_message(chunk)
    # list of subkeys 64 bits BitArray Object
    subk = camellia_key.generate_subkeys()
    subkw = camellia_key.generate_subkw()
    subke = camellia_key.generate_subke()
    data_for_cypher = feistel(subtext, subkw, subk, subke, camellia_key)
    # construction of the ciphertext  from temp1 and temp2
    cipher1 = (agg_128b(data_for_cypher[1]) << 64)
    cipher2 = agg_128b(data_for_cypher[0])
    cipher = cipher1 | cipher2
    return cipher



"""
    Decryption of a 128 bits cipher with camellia key
    @:param chunk_cipher    a chunk of the cipher message
    @:param camellia_key    Camellia Key object
"""


def decryption(chunk_cipher, camellia_key):
    subtext_cipher = divide_message(chunk_cipher)
    invsubkw = inverse_subkweys(camellia_key.generate_subkw())
    invsubk = inverse_subk(camellia_key.generate_subkeys())
    invsubke = inverse_subke(camellia_key.generate_subke())
    data_for_decipher = feistel(subtext_cipher, invsubkw, invsubk, invsubke, camellia_key)
    decipher1 = (agg_128b(data_for_decipher[0]) << 64)
    decipher2 = agg_128b(data_for_decipher[1])
    plaintext = decipher1 | decipher2
    return plaintext


def feistel(subtext, subkw, subk, subke, camellia_key):
    """
        @:param subtext         list of 2 64 bits BitArray Object
        @:param subkw           list of subkweys 64bits BitArray Object
        @:param subk            list of subkeys 64bits BitArray Object
        @:param subke           list of subke-eys 64bits BitArray Object
        @:param camellia_key    Camellia Key object
    """
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


def f_function(inputdata, sigma):
    """
        f_function
        @:param     inputdata 64 bits
        @:param     subkey 64 bits

        @:var       SBOX1[], SBOX2[], SBOX3[], SBOX4[]

        @:return    fout 64 bits
    """
    x = inputdata ^ sigma
    t1 = x >> 56
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >> 8) & MASK8
    t8 = x & MASK8
    t1 = SBOX1[t1.int]
    t2 = SBOX2(t2.int)
    t3 = SBOX3(t3.int)
    t4 = SBOX4(t4.int)
    t5 = SBOX2(t5.int)
    t6 = SBOX3(t6.int)
    t7 = SBOX4(t7.int)
    t8 = SBOX1[t8.int]
    t1 = BitArray(Bits(int=t1, length=64))
    t2 = BitArray(Bits(int=t2, length=64))
    t3 = BitArray(Bits(int=t3, length=64))
    t4 = BitArray(Bits(int=t4, length=64))
    t5 = BitArray(Bits(int=t5, length=64))
    t6 = BitArray(Bits(int=t6, length=64))
    t7 = BitArray(Bits(int=t7, length=64))
    t8 = BitArray(Bits(int=t8, length=64))
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
    varand = x1 & k1
    varand.rol(1)
    x2 ^= varand
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
    varand = y1 & k1
    varand.rol(1)
    y2 ^= varand
    flinvout = (y1 << 32) | y2
    return flinvout

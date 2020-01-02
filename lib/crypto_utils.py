import binascii
import bitstring
import inspect
import os
import random
import re
from math import sqrt


def get_depth():
    """
    @brief      Gets the depth of the function
    @return     The depth.
    """
    return len(inspect.stack()) - 3


class DHParams(object):
    """
    Grouping p, q and g parameters of Diffie Hellman Exchange
    """

    def __init__(self, p, q, g, tup):
        self.p = p
        self.q = q
        self.g = g
        self.length = tup

    def __repr__(self):
        return "%s(p=%r, q=%r, g=%r, lenth=%r)" % (
            self.__class__.__name__, self.p, self.q, self.g, self.length)

    def __str__(self):
        return "(p=%r, q=%r, g=%r)" % (
            self.p, self.q, self.g)


def create_key_pairs(length):
    """
    RSA algo asymétrique
    :param length:
    :return:
    """
    # choose two primes numbers P and Q
    p = getPrime(length)
    q = getPrime(length)
    if p == q:
        create_key_pairs(length)
    # take N = P x Q
    n = p * q
    # M = (P-1) x (Q-1)
    m = (p - 1) * (q - 1)
    # find C which is prime with M (PGCD)
    while True:
        c = genKey(length)
        if pgcd(c, m) == 1:
            break
    # public key = C et N
    pukey = [c, n]
    # calcul U tq C x U + M x V = 1 (algo d'euclide etendu)
    coefs = pgcde(c, m)
    # clé privé : U et N
    prikey = [coefs[1], n]
    return pukey, prikey


class Key(object):
    """ Represents a key object """

    def __init__(self, params, pukey, prikey):
        """

        :param params:
        :param pukey: public key
        :param prikey: private key
        """
        self.param = params
        self.public_key = pukey
        self.private_key = prikey

    def __repr__(self):
        return "%s(param=%r, public_key=%r, private_key=%r)" % (
            self.__class__.__name__, self.param, self.public_key, self.private_key)

    def __str__(self):
        return "Key:\n\tparam={}\n\tpublic_key={}\n\tprivate_key={}\n".format(
            self.param, self.public_key, self.private_key)

    def store(self, folder):
        # store public key
        add_pukey = "{}/public_key".format(folder)
        file_pukey = open(add_pukey, 'wb+')
        file_pukey.write(self.public_key)
        file_pukey.close()
        # store private key
        add_prikey = "{}/private_key".format(folder)
        file_prikey = open(add_prikey, 'wb+')
        file_prikey.write(self.private_key)
        file_prikey.close()
        # print the file address of the keys
        print("Your public key has been saved in {} \n".format(add_pukey))
        print("Your private key has been saved in {} \n".format(add_prikey))


# ===========================================
#               Miller-Rabin test
# Lien:     https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#Python
# ===========================================
def _try_composite(a, d, n, s):
    if pow(a, d, n) == 1:
        return False
    for i in range(s):
        if pow(a, 2 ** i * d, n) == n - 1:
            return False
    return True  # n  is definitely composite


def is_prime(n, _precision_for_huge_n=16):
    """

    :param n:
    :param _precision_for_huge_n:
    :return:
    """
    if n in _known_primes or n in (0, 1):
        return True
    if any((n % p) == 0 for p in _known_primes):
        return False
    d, s = n - 1, 0
    while not d % 2:
        d, s = d >> 1, s + 1
    # Returns exact according to http://primes.utm.edu/prove/prove2_3.html
    if n < 1373653:
        return not any(_try_composite(a, d, n, s) for a in (2, 3))
    if n < 25326001:
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5))
    if n < 118670087467:
        if n == 3215031751:
            return False
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7))
    if n < 2152302898747:
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11))
    if n < 3474749660383:
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13))
    if n < 341550071728321:
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17))
    # otherwise
    return not any(_try_composite(a, d, n, s)
                   for a in _known_primes[:_precision_for_huge_n])


_known_primes = [2, 3]
_known_primes += [x for x in range(5, 1000, 2) if is_prime(x)]


# =========================================================

def pgcde(a, b):
    """
    @brief      PGCD étendu avec les 2 coefficients de bézout u et v
    @:param     a       un entier
    @:param     b       un entier
    @:return    r       pgcd(a,b)
    @:return    u,v     entiers tq a*u + b*v = r
        SI r = 1 (pgcd(a,b) = 1):
            - u est l'inverse modulaire de a mod(b)
            - v est l'inverse modulaire de b mod(a)
    @lien       http://python.jpvweb.com/python/mesrecettespython/doku.php?id=pgcd_ppcm
    """
    r, u, v = a, 1, 0
    rp, up, vp = b, 0, 1
    while rp != 0:
        q = r // rp
        rs, us, vs = r, u, v
        r, u, v = rp, up, vp
        rp, up, vp = (rs - q * rp), (us - q * up), (vs - q * vp)
    pgcd_coefs = [r, u, v]
    return pgcd_coefs


def pgcd(a, b):
    """
    @brief       pgcd(a,b): calcul du 'Plus Grand Commun Diviseur' entre les 2 nombres entiers a et b
    @lien        http://python.jpvweb.com/python/mesrecettespython/doku.php?id=pgcd_ppcm
    @:param      a     Une valeur
    @:param      b     Une valeur
    @:return     Le Plus Grand Commun Diviseur entre a et b
    """
    while b != 0:
        r = a % b
        a, b = b, r
    return a


def bytes_inv(bts, modulo):
    """
    @brief      Trouve l'inverse d'un bytes dans Z_modulo
    @:param     bts     Le bytes
    @:param     modulo  Le modulo
    @:return            L'inverse du bytes dans Z_modulo
    """
    val = bytes2int(bts)

    return inv(val, modulo)


def inv(val, modulo):
    """
    @brief     Trouve l'inverse d'un entier dans Z_modulo
    @:param    val        La valeur
    @:param    modulo     Le modulo
    @:return              L'inverse de la valeur dans Z_modulo
    """
    r, u, v = pgcde(val, modulo)

    if r == 1:
        return u % modulo
    else:
        return None


def exp_rapide(a, n):
    """
    @brief      exponentiation rapide (calcul de a^n). Version itérative
    @:param     a     La base
    @:param     n     L'exposant
    @:return    a^n
    """
    b, m = a, n
    r = 1
    while m > 0:
        if m % 2 == 1:
            r = r * b
        b = b * b
        m = m // 2
    return r


def fac(n):
    """
    @brief      Factorisation en facteur premier
    @:param     n       La valeur à factoriser
    @:return            tableau des facteurs premier
    """
    step = lambda x: 1 + (x << 2) - ((x >> 1) << 1)
    maxq = int(sqrt(n))
    d = 1
    q = n % 2 == 0 and 2 or 3
    while q <= maxq and n % q != 0:
        q = step(d)
        d += 1
    return q <= maxq and [q] + fac(n // q) or [n]


# ===============================================================================

def getPrime(nb_bytes):
    """
    @brief      Génère un nombre premier de nb_bytes octets
    @:param     nb_bytes    Le nombre d'octet
    @:return    q           Le nombre premier
    """
    depth = get_depth()
    print("{}getPrime: Generate a {} bytes long prime".format(depth * "\t", nb_bytes))
    i = 0
    while True:
        i += 1
        q = bytes2int(genKey(nb_bytes, False, i))
        if is_prime(q):
            print('')
            break
    return q


def genKey(nb_bytes, print_num=True, i=1):
    """
    @brief       Génère une clé aléatoire de nb_bytes octets
    @:param      nb_bytes   Le nombre d'octet
    @:param      print_num  afficher la clé générée
    @:param      i          Le nombre d'itération
    @:return     key        La clé générée en bytes
    """
    depth = get_depth()
    print("{}genKey: Generate a {} bytes long random number. try {}".format(depth * "\t", nb_bytes, i), end="\r")
    while True:
        key = os.urandom(nb_bytes)
        if bytes2int(key) != 0:
            break
    if print_num:
        key_hex = key.hex()
        print(':'.join(a + b for a, b in zip(key_hex[::2], key_hex[1::2])))
    return key


def genVector():
    """
        Generate a initialization vector of 128 bits
        @:return    vector  128 bits number
    """
    vector = genKey(128)
    return vector


def Schnorr_group(nb_small, nb_big):
    """
    @brief      Génére un group de Schnorr

    @param      nb_small  Le nombre d'octes pour q
    @param      nb_big    Le nombre d'octes pour p

    @return     Le groupe de schorr généré dans une classe DHParams
    """
    depth = get_depth()
    print("{}Schnorr_group: Generate prime q".format(depth * "\t"))
    q = getPrime(nb_small)

    print("{}Schnorr_group: Generate prime p".format(depth * "\t"))
    i = 1
    # r = bytes2int(genKey(nb_big - nb_small, False, i))
    r = bytes2int(genKey(nb_big, False, i))
    while True:

        p = r * q + 1
        # p = r - ((r % (2*q)) - 1)
        if is_prime(p) and p != 1:
            print('')
            break
        else:
            i += 1
            r = bytes2int(genKey(nb_big - nb_small, False, i))
            # r = bytes2int(genKey(nb_big, False, i))

    print("{}Schnorr_group: generate g".format(depth * "\t"))
    while True:
        h = random.randint(2, p - 2)

        g = pow(h, r, p)
        if g != 1:
            break
    return DHParams(p, q, g, (nb_small, nb_big))


def parseKey(printed_key):
    """
    @brief      Fonction permettant de parser un clé en bytes du format suivant XX:XX:XX:XX:XX

    @param      printed_key  La clé a parser

    @return     La clé en bytes
    """
    if type(re.match('^([0-9a-f]{2}:)*[0-9a-f]{2}$', printed_key)) is not None:
        # Problem : rand_hex dont exist??
        hexa = rand_hex.replace(":", "")
        return binascii.unhexlify(hexa)
    else:
        print("Wrong key structure")
        return None


def bytesToString(byt):
    """
    @brief      Affiche un bytes en str

    @param      byt   Le bytes à afficher

    """
    key_hex = byt.hex()
    print(':'.join(a + b for a, b in zip(key_hex[::2], key_hex[1::2])))


# ===========================================
#     Conversions entre différents formats
# ===========================================

def bin2hex(binstr):  # binstr : "0bAAA" ou 0bAAA
    if type(binstr) == str:
        return hex(int(binstr, 2))
    else:
        return hex(binstr)
    # return "0xAAA"


def hex2bin(hexstr):  # hexstr : "0xAAA" ou 0xAAA
    if type(hexstr) == str:
        return bin(int(hexstr, 16))
    else:
        return bin(int(str(hexstr), 16))
    # return "0bAAA"


def hex2int(hexstr):  # hexstr : "0xAAA" ou 0xAAA
    if type(hexstr) == str:
        return int(hexstr, 16)
    else:
        return int(str(hexstr), 16)
    # return AA


def bin2int(binstr):  # binstr : "0bAAA" ou 0bAAA
    if type(binstr) == str:
        return int(binstr, 2)
    else:
        return int(str(binstr), 2)
    # return AA


def bytes2int(bts):
    return int.from_bytes(bts, byteorder='big')


def int2bytes(val, nb_bytes):
    return val.to_bytes(nb_bytes, byteorder='big')


# ===========================================
#            rotation binaire
# lien :  X http://python.jpvweb.com/python/mesrecettespython/doku.php?id=binaire
#         X https://gist.github.com/cincodenada/6557582
#         https://www.geeksforgeeks.org/rotate-bits-of-an-integer/
# ===========================================

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
    ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))


def int_rol(intnb, rotation):
    return rol(intnb, rotation, len(bin(intnb)) - 2)


def int_ror(intnb, rotation):
    return ror(intnb, rotation, len(bin(intnb)) - 2)


def bytes_rol(bts, r_bits):
    """
    Rotate left a bytes number for r_bits time
    :param bts: byte number
    :param r_bits: number of rotation we want to do
    :return: the bit number rotated
    """
    temp = bytes2int(bts)
    temp = rol(temp, r_bits, len(bts) * 8)
    return int2bytes(temp, len(bts))


def bytes_ror(bts, r_bits):
    """
    Rotate right a bit number for r_bits time
    :param bts: bit number
    :param r_bits: number of rotation we want to do
    :return: the bit number rotated
    """
    temp = bytes2int(bts)
    temp = ror(temp, r_bits, len(bts) * 8)
    return int2bytes(temp, len(bts))


# ===========================================
#            Opérations sur les bytes
# ===========================================


def bytes_or_bytes(bts1, bts2):  # bts | bts
    return int2bytes(bytes2int(bts1) | bytes2int(bts2), len(bts1))


def bytes_and_bytes(bts1, bts2):  # bts & bts
    return int2bytes(bytes2int(bts1) & bytes2int(bts2), len(bts1))


def bytes_xor_bytes(bts1, bts2):  # bts ^ bts
    return int2bytes(bytes2int(bts1) ^ bytes2int(bts2), len(bts1))


def bytes_or_int(bts1, val):  # bts | int
    return int2bytes(bytes2int(bts1) | val, len(bts1))


def bytes_and_int(bts1, val):  # bts & int
    return int2bytes(bytes2int(bts1) & val, len(bts1))


def bytes_xor_int(bts1, val):  # bts ^ int
    return int2bytes(bytes2int(bts1) ^ val, len(bts1))


def bytes_times_int(bts1, val):
    return int2bytes((bytes2int(bts1) * val) % (exp_rapide(2, len(bts1) * 8) + 1), len(bts1))


def bytes_plus_bytes(bts1, bts2):  # bts + bts
    return int2bytes((bytes2int(bts1) + bytes2int(bts2)) % exp_rapide(2, len(bts1) * 8), len(bts1))


def bytes_minus_bytes(bts1, bts2):  # bts - bts
    return int2bytes((bytes2int(bts1) - bytes2int(bts2)) % exp_rapide(2, len(bts1) * 8), len(bts1))


def bytes_complement(bts):  # ~bts
    return int2bytes(- bytes2int(bts) - 1, len(bts))


def bytes_lshift(bts, int):  # bts << int
    return bitstring.BitArray(bytes=bts) << int


def bytes_rshift(bts, int):  # bts >> int
    return bitstring.BitArray(bytes=bts) >> int


def padd(message, chunk_size):
    # message need to be in bit or to be a bit number
    # chunk size is a integer
    if len(message) % chunk_size != 0:
        message


# ===========================================
#            Block cipher mode
# ===========================================

def ECB(function, file_in, file_out, chunk_size, key):
    """
    @brief      Mode ECB: chiffre/déchiffre le fichier avec la fonction de
                chiffrement et la clé passée en paramètre dans un autre fichier

    @:param      function    La fonction de chiffrement
    @:param      file_in     L'adresse du fichier d'entrée
    @:param      file_out    l'adresse du fichier de sortie
    @:param      chunk_size  La taille du bloc en bytes
    @:param      key         La clé en bytes

    """
    if not isinstance(key, bytes):
        raise TypeError("key must be set to bytes")
    with open(file_in, 'rb') as f:
        s = open(file_out, 'wb+')
        for chunk in iter(lambda: f.read(chunk_size), b''):
            if len(chunk) != chunk_size:
                chunk += bytes(chunk_size - len(chunk))
            s.write(function(chunk, key))
        s.close()


class CBC(object):
    """Classe pour le mode CBC"""

    @staticmethod
    def cipher(function, file_in, file_out, chunk_size, key, init_vector):
        """
        @brief      Mode CBC chiffrement: chiffre le fichier avec la fonction de
                    chiffrement, la clé et le vecteur initial passé en
                    paramètre dans un autre fichier

        @:param      function    La fonction de chiffrement
        @:param      file_in     L'adresse du fichier d'entrée
        @:param      file_out    L'adresse du fichier de sortie
        @:param      chunk_size  La taille du bloc en bytes
        @:param      key         Camellia key object
        @:param      init_vector  Le vecteur initial

        """
        if not isinstance(init_vector, bytes):
            raise TypeError("init_vector must be set to bytes")
        if not isinstance(key, bytes):
            raise TypeError("key must be set to bytes")
        if len(init_vector) != chunk_size:
            raise ValueError("init_vector must be the same size of the chunk size")

        with open(file_in, 'rb') as f:
            s = open(file_out, 'wb+')
            last_bytes = init_vector
            for chunk in iter(lambda: f.read(chunk_size), b''):
                if len(chunk) != chunk_size:
                    chunk += bytes(chunk_size - len(chunk))
                chunk = bytes_xor_bytes(chunk, last_bytes)
                last_bytes = function(chunk, key)
                s.write(last_bytes)
            s.close()
        f.close()

    @staticmethod
    def decipher(function, file_in, file_out, chunk_size, key, init_vector):
        """
        @brief      Mode CBC déchiffrement: déchiffre le fichier avec la fonction de
                    chiffrement, la clé et le vecteur initial passé en
                    paramètre dans un autre fichier

        @:param      function    La fonction de chiffrement
        @:param      file_in     L'adresse du fichier d'entrée
        @:param      file_out    L'adresse du fichier de sortie
        @:param      chunk_size  La taille du bloc en bytes
        @:param      key         Camellia Key object
        @:param      init_vector  Le vecteur initial

        """
        if not isinstance(init_vector, bytes):
            raise TypeError("init_vector must be set to bytes")
        if not isinstance(key, bytes):
            raise TypeError("key must be set to bytes")
        if len(init_vector) != chunk_size:
            raise ValueError("init_vector must be the same size of the chunk size")

        with open(file_in, 'rb') as f:
            s = open(file_out, 'wb+')
            last_chunk = init_vector
            for chunk in iter(lambda: f.read(chunk_size), b''):
                if len(chunk) != chunk_size:
                    chunk += bytes(chunk_size - len(chunk))
                chunk_decyph = function(chunk, key)
                s.write(bytes_xor_bytes(last_chunk, chunk_decyph))
                last_chunk = chunk
            s.close()
        f.close()


class PCBC(object):
    """Classe pour le mode PCBC"""

    @staticmethod
    def cipher(function, file_in, file_out, chunk_size, key, init_vector):
        """
        @brief      Mode PCBC chiffrement: chiffre le fichier avec la fonction
                    de chiffrement, la clé et le vecteur initial passé en
                    paramètre dans un autre fichier

        @:param      function     La fonction de chiffrement
        @:param      file_in      Le fichier d'entrée
        @:param      file_out     Le fichier de sortie
        @:param      chunk_size   La taille du bloc
        @:param      key          La clé en bytes
        @:param      init_vector  Le vecteur initial

        """
        if not isinstance(init_vector, bytes):
            raise TypeError("init_vector must be set to bytes")
        if not isinstance(key, bytes):
            raise TypeError("key must be set to bytes")
        if len(init_vector) != chunk_size:
            raise ValueError("init_vector must be the same size of the chunk size")

        with open(file_in, 'rb') as f:
            s = open(file_out, 'wb+')
            last_bytes = init_vector
            for chunk in iter(lambda: f.read(chunk_size), b''):
                if len(chunk) != chunk_size:
                    chunk += bytes(chunk_size - len(chunk))
                chunk_xor = bytes_xor_bytes(chunk, last_bytes)
                last_bytes = function(chunk_xor, key)
                s.write(last_bytes)
                last_bytes = bytes_xor_bytes(last_bytes, chunk)
            s.close()

    @staticmethod
    def decipher(function, file_in, file_out, chunk_size, key, init_vector):
        """
        @brief      Mode PCBC déchiffrement: déchiffre le fichier avec la
                    fonction de chiffrement, la clé et le vecteur initial
                    passé en paramètre dans un autre fichier

        @:param      function     La fonction de chiffrement
        @:param      file_in      Le fichier d'entré
        @:param      file_out     Le fichier de sortie
        @:param      chunk_size   La taille du bloc
        @:param      key          La clé en bytes
        @:param      init_vector  Le vecteur initial

        """
        if not isinstance(init_vector, bytes):
            raise TypeError("init_vector must be set to bytes")
        if not isinstance(key, bytes):
            raise TypeError("key must be set to bytes")
        if len(init_vector) != chunk_size:
            raise ValueError("init_vector must be the same size of the chunk size")

        with open(file_in, 'rb') as f:
            s = open(file_out, 'wb+')
            last_chunk = init_vector
            for chunk in iter(lambda: f.read(chunk_size), b''):
                if len(chunk) != chunk_size:
                    chunk += bytes(chunk_size - len(chunk))
                chunk_decyph = function(chunk, key)
                chunk_decyph = bytes_xor_bytes(last_chunk, chunk_decyph)
                s.write(chunk_decyph)
                last_chunk = bytes_xor_bytes(chunk, chunk_decyph)
            s.close()


# ===========================================
#            IO for yaml File
# ===========================================
"""
def read_yaml(file):
    with open(file, 'r') as infile:
        return yaml.load(infile)

def write_yaml(data, file):
    with open(file, 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)
"""

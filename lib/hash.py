import numpy as np
from lib import crypto_utils as cu

# r : le nombre de bits par bloc de sortie
r = 512 #r=1088 for SHA-256
# n : le nombre de blocs de sortie (arbitraire, min 2)
n = 4 #128 for SHA-256
# length : nb de bits
length = 8 #256 for SHA-256
c=512

def padding(flux):
    # add 1 at the end of the flux
    # add zero sequence
    # add flux length on the last 64 bits
    return

def concatenation(chain, table):
    return

def decoupe(flux, length):
    return

def hash_function(message):
    #construction à partir d'une fonction de compression h
    #padding M = k.b bits
    #découpage de M en bloc de taille b
    #itération de la fonction h
    return hash

def sponge_function(flux):
    """

    :param flux: binascii
    :return:
    """
    # table de bits initialisée à 0
    state = np.zeros(length, dtype=bytes)
    # chaîne de sortie initialisée à vide
    sortie = str("")
    #absorption phase
    padded_flux = padding(flux)
    blocs = decoupe(padded_flux)
    for bloc in blocs:
        # hash_function est une fonction de transformation de length bit
        state = hash_function(cu.bytes_xor_bytes(state[0:r],bloc))
    #essorage phase
    for i in range(0, n):
        sortie = concatenation(sortie, state[0:r])
        state = hash_function(state)
    return sortie

def hash_message(file_adress, hash_out_adress):
    """

    :param file_adress: address of the file we want to hash
    :param hash_out_adress: address where we will find the hash
    """
    #open in binascii
    f = open(file_adress,'rb')
    message = f.read()
    hash = sponge_function(message)
    fh = open(hash_out_adress, 'wb+')
    fh.write(hash)


def verify_hash(file_adress, hash_adress):

    return
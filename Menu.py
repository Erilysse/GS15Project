import os

import Camellia as cam
import crypto_utils as cu

from lib import hash

os.chdir("tests")


def switchcase(option):
    switcher = {
        1: generate_key_pairs,
        2: generate_certif,
        3: check_certif,
        4: share_secret_key,
        5: encrypt,
        6: decrypt,
        7: sign,
        8: verify_sign,
        9: all
    }
    # Get the function from switcher dictionary
    func = switcher.get(option, lambda: "Option incorrect")
    return func()


print("Hi ! This is the Menu.")
print("Please, choose an option: \n"
      "1 : Generate public / private key pairs \n"  # pour le certificateur et le site
      "2 : Generate a certificate \n"
      "3 : Check the validity of a certificate \n"
      "4 : Share a secret key \n"  # camellia private key exchange in diffie hellman
      "5 : Encrypt a message \n"  # camellia encryption
      "6 : Decrypt a message \n"  # camellia decryption
      "7 : Sign a message \n"  # fonction de hachage + algorithme de signature
      "8 : Verify a signature \n"  # extraire la signature, le document, réappliquer la fonction de hachage, 
      # et vérifier si c = 
      "9 : Complete all options \n"
      )

option = input("Specify the option : ")
option = int(option)
print("You have chosen the option", option)
switchcase(option)


def generate_key_pairs():
    """
      creation of public key (implementation RSA)
      # choose two primes numbers P and Q
      # take N = P x Q
      # M = (P-1) x (Q-1)
      # find C which is prime with M (PGCD)
      #public key = N et C

      # creation of private key
      # calcul U tq C x U + M x V = 1 (algo d'euclide etendu)
      # clé privé : U et N
      # creation of key object with public and private parts
      """


# certificateur signe avec sa clé privé la clé publique du site (s priv c(pub s))
def generate_certif(private_key_certif=None, public_key_site=None):
    public_key_site
    private_key_certif

    return


# certificateur donne sa clé publique pub c et visiteur vérifie le certificate
def check_certif(public_key_certif=None):
    public_key_certif

    return


def share_secret_key():
    # diffie hellman exchange
    return


def encrypt():
    # input of the file we will encrypt
    file_in_address = input("Where is the file you want to encrypt ? Precise an address like C:/Documents/etc.. : \n")
    # generate camellia key
    ckey_address = str(input("Where is your private key file ? Precise an address"))
    ckey = cam.CamelliaKey(ckey_address)
    # input of the cipher mode we will use for the encryption
    print("Please, choose a cipher mode: \n"
          "1 : ECB (Electronic Code Book)\n"
          "2 : CBC (Cipher Block Chaining)\n"
          "3 : PCBC (Propagating Cipher Block Chaining)\n"
          # "4 : Counter Mode -- not yet implemented \n"
          # "5 : GCM (Galois Counter Mode) -- not yet implemented \n"
          )
    mode = input("Specify the cipher mode :")
    mode = int(mode)
    if mode == 1:
        print("the cipher mode is EBC. \n")
        cu.ECB(cam.encryption, file_in_address, "encrypted_message_ecb.txt", 128, ckey)
    elif mode == 2:
        print("the cipher mode is CBC. \n")
        cu.CBC.cipher(cam.encryption, file_in_address, "encrypted_message_cbc.txt", 128, ckey, cu.genVector())
    else:
        print("the cipher mode is PCBC. \n")
        cu.PCBC.cipher(cam.encryption, file_in_address, "encrypted_message_pcbc.txt", 128, ckey, cu.genVector())


def sign():
    file_in_address = input("Where is the file you want to sign ?")
    file_in_address = str(file_in_address)
    # implementation of hash_message to do with param : file in adress and file out adress
    hash.hash_message(file_in_address, "file_hash_sended.txt")


def verify_sign():
    file_received_address = input("Where is the file you want to verify its signature ?")
    file_received_address = str(file_received_address)
    file_hash_address = input("Where is the hash file ?")
    file_hash_address = str(file_hash_address)
    hash.hash_message(file_received_address, "file_hash_received.txt")
    is_same_hash = hash.compare_hash(file_hash_address, "file_hash_received.txt")
    if is_same_hash:
        print("hashs are conform. file integrity check succeed.")
    else:
        print("hashs are not conform. file integrity check failed.")


def decrypt():
    # input of the file we will decrypt
    file_in_address = input("Where is the file you want to decrypt ? Precise an adress like C:/Documents/etc.. : \n")
    file_in_address = str(file_in_address)
    # find the camelliakey
    ckey_address = str(input("Where is your private key file ? Precise an address"))
    ckey = cam.CamelliaKey(ckey_address)
    # input of the cipher mode we will use for the decryption
    print("Please, choose the cipher mode used: \n"
          "1 : ECB (Electronic Code Book)\n"
          "2 : CBC (Cipher Block Chaining)\n"
          "3 : PCBC (Propagating Cipher Block Chaining)\n"
          # "4 : Counter Mode -- not yet implemented \n"
          # "5 : GCM (Galois Counter Mode) -- not yet implemented \n"
          )
    mode = input("Which one is it ?")
    mode = int(mode)
    if mode == 1:
        print("the cipher mode is EBC. \n")
        cu.ECB(cam.encryption, file_in_address, "encrypted_message_ecb.txt", 128, ckey)
        print("You can find the encrypted data in encrypted_message_ecb.txt")
    elif mode == 2:
        print("the cipher mode is CBC. \n")
        cu.CBC.cipher(cam.encryption, file_in_address, "encrypted_message_cbc.txt", 128, ckey, cu.genVector())
        print("You can find the encrypted data in encrypted_message_cbc.txt")
    else:
        print("the cipher mode is PCBC. \n")
        cu.PCBC.cipher(cam.encryption, file_in_address, "encrypted_message_pcbc.txt", 128, ckey, cu.genVector())
        print("You can find the encrypted data in encrypted_message_pcbc.txt")


def all():
    return

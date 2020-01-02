import os

from lib import Camellia as cam
from lib import crypto_utils as cu
# from lib import signature as si
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
        9: all,
    }
    # Get the function from switcher dictionary
    func = switcher.get(option, lambda: "option incorrect")
    return func()

def generate_key_pairs():
    """
    Use of RSA keys
    """
    # ask the folder where the keys will be stored
    folder_out_address = input("Enter folder address in which to save the keys :\n")
    # ask the length of the keys we want
    length = int(input("Which length do you want for your keys ?"))
    # creation of public key
    keys = cu.create_key_pairs(length)
    # creation of key object with public and private parts
    keys_object = cu.Key(0, keys[0], keys[1])
    keys_object.store(folder_out_address)


# certificateur signe avec sa clé privé
# la clé publique du site (s priv c(pub s))
def generate_certif(public_key):

    return


# certificateur donne sa clé publique pub c
# et visiteur vérifie le certificate
def check_certif():

    return


def share_secret_key():
    # diffie hellman exchange
    return


def encrypt():
    # input of the file we will encrypt
    file_in_address = input("Where is the file you want to encrypt ? Precise an address like C:/Documents/etc.. : \n")
    # generate camellia key
    ckey_address = input("Where is your private key file ? Precise an address\n")
    length = int(input("Precise the key file's bits number. It must be 128, 192 or 256.\n"))
    ckey = cam.CamelliaKey(ckey_address, length)
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


def sign():
    file_in_address = input("Where is the file you want to sign ?")
    file_in_address = str(file_in_address)
    # need public key, private key for calcul
    # need file in and out adress for hash
    # signature = si.sign_dsa(public_key,private_key,file_in_address,"file_hash_sended.txt")
    # open("signature").write(signature)

def verify_sign():
    file_received_address = input("Where is the file you want to verify its signature ?")
    file_received_address = str(file_received_address)
    file_hash_address = input("Where is the hash file ?")
    file_hash_address = str(file_hash_address)
    public_key = input("Where is the public key file ?")
    private_key = input("Where is the private key file ?")
    """ si.sign_dsa(public_key, private_key, file_received_address, "file_hash_received.txt")
    is_same_sign = si.compare_sign(file_hash_address, "file_hash_received.txt")
    if is_same_sign:
        print("hashs are conform. file integrity check succeed.")
    else:
        print("hashs are not conform. file integrity check failed.")
"""

def all():
    return



print("Hi ! This is the Menu.")
print("Please, choose an option: \n"
      "1 : Generate public / private key pairs \n"  # RSA ou DSA ?? pour le certificateur et le site
      "2 : Generate a certificate (we suppose we are the certifier) \n"
      "3 : Check the validity of a certificate (we suppose we are the certifier) \n"
      "4 : Share a secret key \n"  # camellia private key exchange in diffie hellman
      "5 : Encrypt a message \n"  # camellia encryption
      "6 : Decrypt a message \n"  # camellia decryption
      "7 : Sign a message \n"  # fonction de hachage + algorithme de signature DSA
      "8 : Verify a signature \n"  # DSA : extraire la signature, le document, réappliquer la fonction de hachage, 
      # et vérifier si c = 
      "9 : Complete all options \n"
      )

option = input("Specify the option : ")
option = int(option)
print("You have chosen the option", option)
switchcase(option)

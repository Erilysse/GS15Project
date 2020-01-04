import os

import yaml

import Camellia as cam
from certificate import *
from dsa import *
import crypto_utils as cu
from diffie_hellman import *

# from lib import hash

primeNumber_Size = 512  # size / quantity of bits to generate the prime number

alice_keys = None
bob_keys = None
shared_key = None
h = None

# ===========================================
"""
    IO for yaml file
"""


def read_yaml(file):
    with open(file, 'r') as infile:
        return yaml.load(infile, Loader=yaml.FullLoader)


def write_yaml(data, file):
    with open(file, 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)


"""
    Function which generate a key pairs : Public and Private. 
"""


def generate_key_pairs():
    """
      creation of public key (implementation RSA)
      choose two primes numbers P and Q
      take N = P x Q
      M = (P-1) x (Q-1)
      find C which is prime with M (PGCD)
      public key : N and C

      creation of private key
      find U as C x U + M x V = 1 (Euclide étendu)
      Private key : U and N
      creation of key object and write the public and private keys in two separate files
    """
    print("Welcome in the \"key admin\" part. What do you want me to do?\n"
          "1: Generate asymmetric keys\n"
          "2: I want to share keys. Create a communication key!\n"
          "3: Sorry, go back to menu.")
    option_part1 = int(input("Choose your option: "))
    if option_part1 == 1:
        print("I'm going to generate asymmetric keys.")
        P = cu.getPrime(primeNumber_Size)
        Q = cu.getPrime(primeNumber_Size)
        N = P * Q
        M = (P - 1) * (Q - 1)  # Euler indicator

        C = cu.getPrime(primeNumber_Size)  # C can't divide M => they are Prime together
        while M % C == 0:
            C = cu.getPrime(primeNumber_Size)
            print('Error : not prime together')

        # public key N, C in a file "publicKey"
        print("Generate a publicKey file.")
        publicKeyFile = open("./files/keys/Gen_publicKey", "w")
        publicKeyFile.write("N=" + str(N) + "\n")
        publicKeyFile.write("C=" + str(C))
        publicKeyFile.close()

        # private key U, N in a file "privateKey"
        print("Generate a privateKey file.")
        r, U, V = cu.pgcde(C, M)  # r = pgcd(C, M)  U is the inverse of C modulo M      V is the inverse of M modulo C
        # print('U is the modular reverse of C' + str(U))
        privateKeyFile = open("./files/keys/Gen_privateKey", "w")
        privateKeyFile.write("U=" + str(U) + "\n")
        privateKeyFile.write("N=" + str(N))
        privateKeyFile.close()
    elif option_part1 == 2:
        share_secret_key()
    elif option_part1 == 3:
        print("Exit.")
    else:
        print("\n Input error.")
    return


def menu_certif():
    print("Welcome in the certificate part. What do you want me to do master?\n"
          "1: I want to sign a message\n"
          "2: I want to verify a signature \n"
          "3: Sorry, go back to menu.")
    option_part6 = int(input("Choose your option: "))
    if option_part6 == 1:
        generate_certif()
    elif option_part6 == 2:
        check_certif()
    elif option_part6 == 3:
        print("Exit.")
    else:
        print("\n Input error.")


# Generate a certificate. Need the certifier's private key and the entity's public key
def generate_certif(private_key_certif=None, public_key_site=None):
    """
    @:brief
    :param private_key_certif:
    :param public_key_site:
    :return:
    """
    # Take Alice and Bob's key from the Diffie Hellman keys exchange.
    # Certifier is Alice and the site has Bob's keys couple

    """
    PROCESS
    STEP 0) certifier creates its own couple ok keys (pub_c, priv_c). Web site do the same (pub_s, priv_s). 
    STEP 1) WebSite creates a certificateObject (with pub_s). He signs pub_s with priv_c.
    Now we have a new parameter : certificate = S_privc(pubs)   
    """

    print("Ok i'm going to create a certificate for the webSite!")
    print("=============================================================================")
    print("First, I need the certifier keys and the website keys too!")

    certifier_keys = DH_gen_keys(128, 64)  # 256, 32 now we have a, g, p and A for Certifier
    website_keys = DH_gen_keys(128, 64)
    write_yaml(certifier_keys, "./files/keys/certifier.yml")
    write_yaml(website_keys, "./files/keys/website.yml")

    print("================================================================")
    print("Starting certificate and thumbprint creations.")
    certif = Certificate()
    certif.create_certificate(website_keys.public_key, certifier_keys.public_key)
    certif.add_thumbprint()

    print("Writing the elements into a file.")
    certificate_file = input("Enter the certificate file name (without the extension): ./files/certificates/")
    write_yaml(certif, "./files/certificates/" + certificate_file + ".yml")
    print("================================================================")
    print("Starting the signature part.")
    print("The certifier is going to sign the thumbprint of pub_s with priv_c")
    # certif = read_yaml("../certificates/" + certificate_file + ".yml") #verification qu'on lit correctement le doc
    signature = DSA_encrypt(certifier_keys, certif.thumbprint.encode('utf-8'))
    print("Signature entered into the certificate file : " + certificate_file)
    certif.add_signed_owner_pubkey(signature)
    write_yaml(certif, "./files/certificates/" + certificate_file + ".yml")
    write_yaml(signature, "./files/certificates/signature_" + certificate_file + ".yml")
    print("================================================================")
    return


# certificateur donne sa clé publique pub c et visiteur vérifie le certificate
def check_certif(public_key_certif=None):
    """
    STEP 2) A visitor wants to verify the website identity.
    He has to decipher the certificate parameter with pub_c.
    The result has to be equal with pub_s.
    """
    print("================================================================")
    print("Certificate Verification initiated!")

    print("Choose the Certificate you want to verify :")
    certificate_name = input("Enter the file name (without the extension): ../files/certificates/")
    certificate = read_yaml("./files/certificates/" + certificate_name + ".yml")
    signature = read_yaml("./files/certificates/signature_" + certificate_name + ".yml")
    print("I need pub_c and S_privc(pub_s)")
    verify = DSA_decrypt(signature)
    if verify:
        print("Everything is safe! The signature is verified.")
    else:
        print("Be careful: the signature is incorrect")
    print("================================================================")
    return


def share_secret_key():
    global alice_keys
    print("I'm going to create a communication key with Diffie Hellman protocol.")
    print("First, I create Alice / Certifier couple keys.")
    # created all parameters
    alice_keys = DH_gen_keys(128, 64)  # now we have a, g, p and A for Alice
    print("Starting generate Bob keys.")
    shared_key_bob, bob_keys = DH_comm_key_Bob(alice_keys.param, alice_keys.public_key)
    shared_key_alice = DH_comm_key_Alice(alice_keys, bob_keys.public_key)
    assert shared_key_alice == shared_key_bob

    print("Generate AliceKeys file.")
    aliceKeyFile = open("./files/keys/AliceKeyfile", "w")
    aliceKeyFile.write("PublicKey = " + str(alice_keys.public_key) + "\n")
    aliceKeyFile.write("PrivateKey = " + str(alice_keys.private_key) + "\n")
    aliceKeyFile.write("SharedKey = " + str(shared_key_alice))
    aliceKeyFile.close()

    print("Generate BobKeys file.")
    bobKeyFile = open("./files/keys/BobKeyfile", "w")
    bobKeyFile.write("PublicKey = " + str(bob_keys.public_key) + "\n")
    bobKeyFile.write("PrivateKey = " + str(bob_keys.private_key) + "\n")
    bobKeyFile.write("SharedKey = " + str(shared_key_bob))
    bobKeyFile.close()
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


def switchcase(case_number):
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
    func = switcher.get(case_number, lambda: "option incorrect")
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

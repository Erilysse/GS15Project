from lib import Camellia as cam
from bitstring import BitArray
from lib import crypto_utils as cu
import os
os.chdir("tests")
 # choose your type of key : 128key or 192key or 256key
a = input("Which key length ? 128 ; 192 ; 256 ?")
if a == 128:
    camellia_key = cam.CamelliaKey("128key.txt", 128)
elif a == 192:
    camellia_key = cam.CamelliaKey("192key.txt", 192)
else:
    camellia_key = cam.CamelliaKey("256key.txt", 256)
"""
    Test 1: encryption and decryption of a simple message (96 bits)
"""
f = open("file_test.txt",'rb')
print("message :")
a = f.read()
print(a)
ms = BitArray(a)
print(ms)
mod = len(ms)%128
if mod != 0:
    ms.append(128-mod)
f.close()
print("message with padding:")
print(ms)
cipher = cam.encryption(ms, camellia_key)
print("cipher :")
print(cipher)
f = open("ciphermessage.txt","wb+")
cipher.tofile(f)
f.close()
f = open("ciphermessage.txt","rb")
ci = BitArray(bytes=f.read())
f.close()
decipher = cam.decryption(ci, camellia_key)
print("decipher:")
print(decipher)
f = open("deciphermessage.txt",'wb+')
decipher.tofile(f)
f.close()
f = open("deciphermessage.txt","rb")
print("message decoded :")
data = f.read()
print(data)
# print(data.decode())
f.close()

    #Test ECB mode with 128 key
"""
"""
message_add = "file_test.txt"
if message_add == "testmessage.txt":
    message = open(message_add, "r").read()
else:
    message = open(message_add,"rb").read()
print("message : ", message)
print(BitArray(message))
cu.ECB(cam.encryption,message_add, "encrypted_text_message.txt", camellia_key)
cu.ECB(cam.decryption,"encrypted_text_message.txt","decrypted_text_message.txt",camellia_key)
f = open("decrypted_text_message.txt","rb")
print("decrypt :", f.read())
print("decrypté:", f.read().decode())

"""
    #Test CBC mode with 128 keys

"""

message = open(message_add,'rb').read()
print("message:", message)
print("message in hex :", BitArray(message))
cu.CBC.cipher(message_add, "encrypted_text_message.txt", camellia_key,cu.genVector())
cipher = open("encrypted_text_message.txt",'rb').read()
cipherB = BitArray(cipher)
print("cipher ", cipherB)
cu.CBC.decipher("encrypted_text_message.txt","decrypted_text_message.txt",camellia_key,"vector.txt")
decipher = open("decrypted_text_message.txt","rb").read()
decipherB = BitArray(cipher)
print("decipher :", decipherB)
print("decode :", decipher.decode())

"""

    # Test PCBC mode with 128 keys -

"""

message = open(message_add,'rb').read()
print("message:", message)
print("message in hex :", BitArray(message))
cu.PCBC.cipher(message_add, "encrypted_text_message.txt", camellia_key,cu.genVector())
cipher = open("encrypted_text_message.txt",'rb').read()
cipherB = BitArray(cipher)
print("cipher ", cipherB)
cu.PCBC.decipher("encrypted_text_message.txt","decrypted_text_message.txt",camellia_key,"vector.txt")
decipher = open("decrypted_text_message.txt","rb").read()
decipherB = BitArray(cipher)
print("decipher :", decipherB)
print("decode :", decipher.decode())
# """


from lib import Camellia as cam
from bitstring import BitArray
import os

os.chdir("tests")

camellia_key = cam.CamelliaKey("128key.txt", 128)
message = "0x0123456789abcdeffedcba9876543210"
ms = BitArray(message)
print(ms)
cipher = cam.encryption(ms,camellia_key)
print(cipher)
decipher = cam.decryption(cipher,camellia_key)
print(decipher)
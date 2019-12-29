from lib import Camellia as cam
from lib import crypto_utils as cu

print("Hello \n")
key = cam.CamelliaKey(128,"tests/128key.txt")
print(key.KL)
print(key.KR)

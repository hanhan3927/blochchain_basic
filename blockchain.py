import hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

secret_en = (b'secret')
secret_ch = ("秘密".encode('utf-8'))

# hash
m = hashlib.sha256()
m.update(secret_ch)
print("hash_chinese:", m.hexdigest())

# RSA
# key generation
key = RSA.generate(2048)
privateKey = key
publicKey =  key.publickey()

# 建立隨機的 AES Session 金鑰
sessionKey = get_random_bytes(16)

# 以 RSA 金鑰加密 Session 金鑰
cipherRSA = PKCS1_OAEP.new(publicKey)
encryptSecret = cipherRSA.encrypt(sessionKey)

# 用 AES 加密訊息
cipherAES = AES.new(sessionKey, AES.MODE_EAX)
ciphertext, tag = cipherAES.encrypt_and_digest(secret_en)

print(ciphertext)
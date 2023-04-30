from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from ascon import ascon_encrypt, ascon_decrypt

def AES_Encrypt(data: bytes, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + cipher.nonce + tag

def AES_Decrypt(ciphertext: bytes, key):
    ciphertext, nonce, tag = ciphertext[:-32], ciphertext[-32:-16], ciphertext[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def DES3_Encrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + cipher.nonce + tag

def DES3_Decrypt(ciphertext: bytes, key):
    ciphertext, nonce, tag = ciphertext[:-24], ciphertext[-24:-8], ciphertext[-8:]
    cipher = DES3.new(key, DES3.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def ASCON_Encrypt(data, key):
    nonce = get_random_bytes(16)
    ciphertext = ascon_encrypt(key = key, nonce = nonce, associateddata = b'', plaintext = data)
    return ciphertext + nonce

def ASCON_Decrypt(ciphertext, key):
    ciphertext, nonce = ciphertext[:-16], ciphertext[-16:]
    data = ascon_decrypt(key = key, nonce = nonce, associateddata = b'', ciphertext = ciphertext)
    return data








if __name__ == '__main__':
    data = b'Trying out a different super secret message that is much longer to confuse \
            the program. asdhfhlkdsfdshflkdsfsahfldsaflkhsaflkhdskfhsahfkshfkjf'
    key = get_random_bytes(16)
    nonce = get_random_bytes(16)

    encrypt_decrypt_pairs = ()

    ciphertext = AES_Encrypt(data, key)
    data = AES_Decrypt(ciphertext, key)
    print(data)

    ciphertext = DES3_Encrypt(data, key)
    data = DES3_Decrypt(ciphertext, key)
    print(data)

    ciphertext = ASCON_Encrypt(data, key)
    data = ASCON_Decrypt(ciphertext, key)
    print(data)

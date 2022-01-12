from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def ctr_prop(plaintext):
    key = get_random_bytes(16)
    encrypt1 = AES.new(key, AES.MODE_CTR)
    nonce = encrypt1.nonce
    encrypt2 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypt1 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypt2 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext1 = encrypt1.encrypt(plaintext.encode())
    ciphertext2 = bytearray(encrypt2.encrypt(plaintext.encode()))
    ciphertext2[3] = ord('b')
    decrypted1 = decrypt1.decrypt(ciphertext1)
    decrypted2 = decrypt2.decrypt(ciphertext2)
    print('CTR')
    print('Original: ' + str(decrypted1))
    print('Error:    ' + str(decrypted2), end='\n\n')


def ofb_prop(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    encrypt1 = AES.new(key, AES.MODE_OFB, iv)
    encrypt2 = AES.new(key, AES.MODE_OFB, iv)
    decrypt1 = AES.new(key, AES.MODE_OFB, iv)
    decrypt2 = AES.new(key, AES.MODE_OFB, iv)
    ciphertext1 = encrypt1.encrypt(plaintext.encode())
    ciphertext2 = bytearray(encrypt2.encrypt(plaintext.encode()))
    ciphertext2[3] = ord('b')
    decrypted1 = decrypt1.decrypt(ciphertext1)
    decrypted2 = decrypt2.decrypt(ciphertext2)
    print('OFB')
    print('Original: ' + str(decrypted1))
    print('Error:    ' + str(decrypted2), end='\n\n')


def cfb_prop(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    encrypt1 = AES.new(key, AES.MODE_CFB, iv)
    encrypt2 = AES.new(key, AES.MODE_CFB, iv)
    decrypt1 = AES.new(key, AES.MODE_CFB, iv)
    decrypt2 = AES.new(key, AES.MODE_CFB, iv)
    ciphertext1 = encrypt1.encrypt(plaintext.encode())
    ciphertext2 = bytearray(encrypt2.encrypt(plaintext.encode()))
    ciphertext2[8] = ord('b')
    decrypted1 = decrypt1.decrypt(ciphertext1)
    decrypted2 = decrypt2.decrypt(ciphertext2)
    print('CFB')
    print('Original: ' + str(decrypted1))
    print('Error:    ' + str(decrypted2), end='\n\n')


def cbc_prop(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    encrypt1 = AES.new(key, AES.MODE_CBC, iv)
    encrypt2 = AES.new(key, AES.MODE_CBC, iv)
    decrypt1 = AES.new(key, AES.MODE_CBC, iv)
    decrypt2 = AES.new(key, AES.MODE_CBC, iv)
    ciphertext1 = encrypt1.encrypt(plaintext.encode())
    ciphertext2 = bytearray(encrypt2.encrypt(plaintext.encode()))
    ciphertext2[4] = ord('b')
    decrypted1 = decrypt1.decrypt(ciphertext1)
    decrypted2 = decrypt2.decrypt(ciphertext2)
    print('CBC')
    print('Original: ' + str(decrypted1))
    print('Error:    ' + str(decrypted2), end='\n\n')


def ecb_prop(plaintext):
    key = get_random_bytes(16)
    encrypt1 = AES.new(key, AES.MODE_ECB)
    encrypt2 = AES.new(key, AES.MODE_ECB)
    decrypt1 = AES.new(key, AES.MODE_ECB)
    decrypt2 = AES.new(key, AES.MODE_ECB)
    pad_bytes = 16 - (len(plaintext) % 16)
    for i in range(0, pad_bytes):
        plaintext = plaintext + chr(pad_bytes)
    ciphertext1 = encrypt1.encrypt(plaintext.encode())
    ciphertext2 = bytearray(encrypt2.encrypt(plaintext.encode()))
    ciphertext2[4] = ord('b')
    decrypted1 = decrypt1.decrypt(ciphertext1)
    decrypted2 = decrypt2.decrypt(ciphertext2)
    print('ECB')
    print('Original: ' + str(decrypted1))
    print('Error:    ' + str(decrypted2), end='\n\n')


if __name__ == '__main__':
    plaintext = 'wireless lab425 wireless lab425 '
    ecb_prop(plaintext)
    cbc_prop(plaintext)
    cfb_prop(plaintext)
    ofb_prop(plaintext)
    ctr_prop(plaintext)
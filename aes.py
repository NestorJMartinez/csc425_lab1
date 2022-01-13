from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad


# def pad(data):
#     pad_bytes = 16 - (len(data) % 16)
#     for i in range(0, pad_bytes):
#         data = data + chr(pad_bytes)
#     return data


def ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def ecb_decrypt(encrypted, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(encrypted)


def cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)


def cbc_decrypt(data, key, iv):
    decipher = AES.new(key, AES.MODE_CBC, iv)
    return decipher.decrypt(data)


def cfb_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(data)


def cfb_decrypt(data, key, iv):
    decipher = AES.new(key, AES.MODE_CFB, iv)
    return decipher.decrypt(data)


def ofb_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(data)


def ofb_decrypt(data, key, iv):
    decipher = AES.new(key, AES.MODE_OFB, iv)
    return decipher.decrypt(data)


def ctr_encrypt(data, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(data)


def ctr_decrypt(data, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(data)


def main():
    # pad the plaintext.
    text = 'this is the wireless security lab'
    padded_text = pad(text, 16)

    # get key & iv. 16 bytes == 128 bits.
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # ECB encryption & decryption.
    ecb_encrypted = ecb_encrypt(padded_text, key)
    ecb_decrypted = ecb_decrypt(ecb_encrypted, key)

    # CBC encryption & decryption.
    cbc_encrypted = cbc_encrypt(padded_text, key, iv)
    cbc_decrypted = cbc_decrypt(cbc_encrypted, key, iv)

    # CFB encryption & decryption.
    cfb_encrypted = cfb_encrypt(text, key, iv)
    cfb_decrypted = cfb_decrypt(cfb_encrypted, key, iv)

    # OFB encryption & decryption.
    ofb_encrypted = ofb_encrypt(text, key, iv)
    ofb_decrypted = ofb_decrypt(ofb_encrypted, key, iv)

    # OFB encryption & decryption.
    nonce = AES.new(key, AES.MODE_CTR).nonce
    ctr_encrypted = ctr_encrypt(text, key, nonce)
    ctr_decrypted = ctr_decrypt(ctr_encrypted, key, nonce)
    print '-' * 30
    print 'text:', text, '\ntext length:', len(text)
    print 'key:', key, '\nkey length:', len(key)
    print 'iv:', iv, '\niv length:', len(iv)
    print 'nonce:', nonce, 'nonce length:', len(nonce)
    print '-' * 30
    # ECB results.
    print 'ECB RESULTS:'
    print 'encrypted message:', ecb_encrypted
    print 'decrypted message:', unpad(ecb_decrypted, 16)
    # CBC results.
    print 'CBC RESULTS:'
    print 'encrypted message:', cbc_encrypted
    print 'decrypted message:', unpad(cbc_decrypted, 16)
    print '-' * 30
    # CFB results.
    print 'CFB RESULTS:'
    print 'encrypted message:', cfb_encrypted
    print 'decrypted message:', cfb_decrypted
    print '-' * 30
    # OFB results.
    print 'OFB RESULTS:'
    print 'encrypted message:', ofb_encrypted
    print 'decrypted message:', ofb_decrypted
    print '-' * 30
    # CTR results.
    print 'CTR RESULTS:'
    print 'encrypted message:', ctr_encrypted
    print 'decrypted message:', ctr_decrypted
    print '-' * 30


if __name__ == "__main__":
    main()

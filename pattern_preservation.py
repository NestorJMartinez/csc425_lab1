from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad(data):
    pad_bytes = 16 - (len(data) % 16)
    for i in range(0, pad_bytes):
        data = data + chr(pad_bytes)
    return data


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
    text = 'wireless lab425 wireless lab425 '
    padded_text = pad(text)

    # get key & iv. 16 bytes == 128 bits.
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # ECB encryption & decryption.
    ecb_encrypted = ecb_encrypt(padded_text, key)
    print '\npattern preservation for ecb:'
    print ecb_encrypted[0:16]
    print ecb_encrypted[16:32]

    # CBC encryption & decryption.
    cbc_encrypted = cbc_encrypt(padded_text, key, iv)
    print '\npattern preservation for cbc:'
    print cbc_encrypted[0:16]
    print cbc_encrypted[16:32]

    # CFB encryption & decryption.
    cfb_encrypted = cfb_encrypt(text, key, iv)
    print '\npattern preservation for cfb:'
    print cfb_encrypted[0:16]
    print cfb_encrypted[16:32]

    # OFB encryption & decryption.
    ofb_encrypted = ofb_encrypt(text, key, iv)
    print '\npattern preservation for ofb:'
    print ofb_encrypted[0:16]
    print ofb_encrypted[16:32]

    # CTR encryption & decryption.
    nonce = AES.new(key, AES.MODE_CTR).nonce
    ctr_encrypted = ctr_encrypt(text, key, nonce)
    print '\npattern preservation for ctr:'
    print ofb_encrypted[0:16]
    print ofb_encrypted[16:32]


if __name__ == "__main__":
    main()

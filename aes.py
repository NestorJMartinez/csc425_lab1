from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


# padding to match the length of the message to encrypt which needs to be a
# multiple of the block size 16.
def pad(data):
    pad_bytes = 16 - (len(data) % 16)
    for i in range(0, pad_bytes):
        data = data + chr(pad_bytes)
    return data


def ECB_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def ECB_decrypt(encrypted, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(encrypted)

def CBC_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)

def CBC_decrypt(data, key, iv):
    decipher = AES.new(key, AES.MODE_CBC, iv)
    return decipher.decrypt(data)

def main():
    # pad the plaintext.
    text = 'this is the wireless security lab'
    padded_text = pad(text)

    # get key & iv. 16 bytes == 128 bits.
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # ECB encryption & decryption.
    ecb_encrypted = ECB_encrypt(padded_text, key)
    ecb_decrypted = ECB_decrypt(ecb_encrypted, key)

    # CBC encryption & decryption.
    cbc_encrypted = CBC_encrypt(padded_text, key, iv)
    cbc_decrypted = CBC_decrypt(cbc_encrypted, key, iv)

    # ECB results.
    print 'ECB RESULTS:'
    print 'key:', key.encode('hex'), '\nkey length:', len(key)
    print 'encrypted message:', ecb_encrypted.encode('hex')
    print 'decrypted message:', unpad(ecb_decrypted, 16)
    print '-'*30
    # CBC results.
    print 'CBC RESULTS:'
    print 'key:', key.encode('hex'), '\nkey length:', len(key)
    print 'iv:', iv.encode('hex'), '\niv length:', len(iv)
    print 'encrypted message:', cbc_encrypted.encode('hex')
    print 'decrypted message:', unpad(cbc_decrypted, 16)


if __name__ == "__main__":
    main()

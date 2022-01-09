from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# padding to match the length of the message to encrypt which needs to be a
# multiple of the block size 16.
def pad(data):
    pad_bytes = 16 - (len(data) % 16)
    for i in range(0, pad_bytes):
        data = data + chr(pad_bytes)
    return data


def ECB_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(data)
    return encrypted

def ECB_decrypt(encrypted, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(encrypted)


def main():
    # pad the plaintext.
    text = 'this is the wireless security lab'
    padded_text = pad(text)

    # get key. 16 bytes == 128 bits.
    key = get_random_bytes(16)

    # ECB encryption & decryption.
    ecb_encrypted = ECB_encrypt(padded_text, key)
    ecb_decrypt = ECB_decrypt(ecb_encrypted, key)

    # ECB results
    print 'key:', key.encode('hex'), '\nkey length:', len(key)
    print 'encrypted message:', ecb_encrypted.encode('hex')
    print 'decrypted message with padding:', ecb_decrypt


if __name__ == "__main__":
    main()

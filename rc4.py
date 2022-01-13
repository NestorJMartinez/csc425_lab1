from Crypto.Cipher import ARC4


def main():
    key = b'\xff' * 5
    text = 'this is the wireless security lab'
    print 'key:', key, '\nkey length:', len(key)
    cipher = ARC4.new(key)
    encrypted = cipher.encrypt(text)
    print 'encrypted message:', encrypted
    cipher = ARC4.new(key)
    print 'decrypted message:', cipher.decrypt(encrypted)


if __name__ == "__main__":
    main()

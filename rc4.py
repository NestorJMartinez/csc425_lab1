from Crypto.Cipher import ARC4


def main():
    key = b'\xff' * 5
    text = 'this is the wireless security lab'

    cipher = ARC4.new(key)
    encrypted = cipher.encrypt(text)
    print encrypted
    lame = ''
    for i in range(0, len(encrypted) - 1):
        lame += encrypted[i].encode('hex')
        lame += ' '
    print lame
    cipher = ARC4.new(key)
    print cipher.decrypt(encrypted)


if __name__ == "__main__":
    main()

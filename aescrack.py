import aes
# Contains the code for discovering the AES-ECB plaintext
TEXT = 'this is the wireless security lab' # gonna pretend I don't know that
KEY = b'\xff' * 16                         # ^

# The basis of this attack, this lets us add a message to the plaintext and recieve the ciphertext
def encryptWithPrefix(prefix):
    alteredText = prefix + TEXT
    return aes.ecb_encrypt(aes.pad(prefix + TEXT), KEY)

# Calls the encryption oracle with extra characters until a new block appears, 
# this reveals the actual message size without padding
def findMessageLength():
    originalLength = len(encryptWithPrefix('')) # should be a multiple of 16
    newLength = originalLength
    i = 0
    while originalLength == newLength:
        i += 1
        newLength = len(encryptWithPrefix('x' * i))
    return originalLength - i

# brute forces a single character of the last block in the ciphertext
# takes a known suffix of len 15, and the prefix to alter the message 
# returns the ascii value of thefirst character of the last block once it is found
def bruteForceSingle(prefix, knownSuffix, block):
    # contains the correct encryption of the block
    t = encryptWithPrefix(prefix)[-32:-16]
    if block == -1: actual = encryptWithPrefix(prefix)[-16:]
    else: actual = encryptWithPrefix(prefix)[16 * block : 16 * (block + 1)]
    t2 = len(actual)
    curByte = 0
    text = chr(curByte)+knownSuffix
    check = encryptWithPrefix(text)[:16]
    while actual != check and curByte < 255:
        curByte += 1
        check = encryptWithPrefix(chr(curByte)+knownSuffix)[:16]
    return (curByte if actual == check else -1)

# uses bruteForceSingle to crack the last encrypted block based on its padding scheme
# returns the last 15 characters of the plaintext 
def breakPaddedBlock(prefixLen):
    plaintext = ''
    padLen = 15
    while len(plaintext) < 15:
        prefix = 'x' * prefixLen
        suffix = plaintext + chr(padLen) * padLen
        byte  = bruteForceSingle(prefix, suffix, -1)
        if byte == -1: 
            exit()
        plaintext = chr(byte) + plaintext
        print("Partial: " + plaintext)
        padLen -= 1
        prefixLen = (prefixLen + 1) % 16
    return plaintext

# uses bruteForceSingle to crack a block using a partial plaintext
def breakUnpaddedBlock(plaintext, block, messageLen):
    prefixLen = 15
    for i in range(16):
        prefix = 'x' * prefixLen
        suffix = plaintext[:15]
        byte  = bruteForceSingle(prefix, suffix, block)
        if byte == -1: 
            exit()
        plaintext = chr(byte) + plaintext
        print("Partial: " + plaintext)
        prefixLen = (prefixLen + 1) % 16
        if len(plaintext) == messageLen: break
    return plaintext

def main():
    plaintext = ''
    messageLength = findMessageLength()
    prefixLen = (17 - (messageLength % 16)) % 16
    plaintext = breakPaddedBlock(prefixLen)
    block = -2
    # loops through the remaining blocks and decrypts using a partial plaintext
    while len(plaintext) < messageLength:
        plaintext = breakUnpaddedBlock(plaintext, block, messageLength)
        block -= 1
    print("Final: " + plaintext)

if __name__ == "__main__":
    main()
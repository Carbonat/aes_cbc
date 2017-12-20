from Crypto.Cipher import AES
import os

block_size = 128 // 8
debug = False #True

def padding(text: bytes) -> bytes:
    pad_size = block_size - len(text) % block_size
    if debug:
       print('pad_size = {}'.format(pad_size))
    return bytes(bytearray(text) + bytearray([pad_size] * pad_size))

def unpad(text: bytes) -> bytes:
    pad_size = text[-1]
    if debug:
        print('pad_size = {}'.format(pad_size))
    if text[-pad_size:] == bytes([pad_size] * pad_size):
        return text[:-pad_size]
    return text

def encrypt(iv: bytes, key: bytes, plaintext: str) -> bytes:
    p = bytes(plaintext, 'ascii')
    padded = padding(p)
    c0 = iv
    if debug:
        print('\nencryption')
        print('p = {}'.format(p))
        print('len(p) = {}'.format(len(p)))
        print('padded = {}'.format(padded))
        print('len(padded) = {}'.format(len(padded)))
    aes = AES.new(key)
    cipher = bytearray()
    for i in range(0, len(padded), block_size):
        c1 = padded[i:i + block_size]
        inp = bytes((b0 ^ b1 for b0, b1 in zip(c0, c1)))
        enc_res = bytearray(aes.encrypt(inp))
        cipher += enc_res

        if debug:
            print('i = {}'.format(i))
            print('i+block_size = {}'.format(i + block_size))
            print('c0 = {}'.format(c0))
            print('c1 = {}'.format(c1))
            print('inp = {}'.format(inp))
            print('enc_res = {}\n'.format(enc_res))

        c0 = enc_res

    if debug:
        print('\ncipher = {}\n'.format(cipher))
    
    return bytes(cipher)

def decrypt(iv: bytes, key: bytes, ciphertext: bytes) -> str:
    c0 = iv
    aes = AES.new(key)

    if debug:
        print('decrypt')
    
    plaintext = bytearray()
    for i in range(0, len(ciphertext), block_size):
        c1 = ciphertext[i:i + block_size]
        decr_res = bytes(aes.decrypt(c1))
        out = bytes((b0 ^ b1 for b0, b1 in zip(c0, decr_res)))
        plaintext += out

        if debug:
            print('\ni = {}'.format(i))
            print('c1 = {}'.format(c1))
            print('len(c1) = {}'.format(len(c1)))
            print('decr_res = {}'.format(decr_res))
            print('c0 = {}'.format(c0))
            print('out = {}'.format(out))

        c0 = c1
    
    if debug:
        print('\nplaintext = {}'.format(plaintext))

    plaintext = unpad(plaintext)
    if debug:
        print('unpaded = {}'.format(plaintext))
    return ''.join(map(chr, plaintext))

if __name__ == '__main__':
    key_size = -1
    plaintext = str()
    if debug:
        key_size = 256
        #plaintext = 'abcdefgh123456789'
        #plaintext = 'a'
        plaintext = 'The Advanced Encryption Standard (AES), also known by its original name Rijndael'
    else:
        while key_size not in (128, 192, 256):
            key_size = int(input('Key size:\n'))
        while not plaintext.strip():
            plaintext = input('Enter plaintext:\n')

    key = os.urandom(key_size // 8)
    print('\nKey:\n{}\n'.format(key.hex()))

    iv = os.urandom(block_size)
    print('IV:\n{}\n'.format(iv.hex()))

    cipher = encrypt(iv, key, plaintext)
    print('cipher:\n{}'.format(cipher.hex()))

    text = decrypt(iv, key, cipher)
    print('text:\n{}'.format(text))

    print(len(text))
    print(len(plaintext))
    print(plaintext == text)

import Crypto.Util.number

import sys

def encrypt(plain, e, N):
    return pow(plain,e,N)

def decrypt(cipher, d, N):
    return pow(cipher,d,N)

def test(message, bits=1024):

    #print ("No of bits in prime is ",bits)

    p=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    #print ("\nRandom n-bit Prime (p): ",p)

    q=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    #print ("\nRandom n-bit Prime (q): ",q)

    N=p*q

    #print ("\nN=p*q=",N)

    PHI=(p-1)*(q-1)

    #print ("\nPHI (p-1)(q-1)=",PHI)

    e=65537
    #print ("\ne=",e)
    d=Crypto.Util.number.inverse(e,PHI)
    #print ("d=",d)

    #print ("\nCount of decimal digits (p): ",len(str(p)))
    #print ("Count of decimal digits (N): ",len(str(N)))

    # M=5

    #sample key 32 bytes
    # M=b'\xfa\x90\xd4\x00F\x92g\xcaA\x16\x05%\xb2H\xf9\x97\x9c\x1c\xe4\xc6\xcd\xf1\x9b\xe3/\x1b\x8c\x96\xb5Q\x8d\x8a'
    if isinstance(message, str):
        message = message.encode('utf-8')

    M=int.from_bytes(message, byteorder='big')
    #print ("\n\n=== Let's try these keys ==")
    #print ("\nRSA Message: ",M)
    enc=encrypt(M, e, N)
    #print ("RSA Cipher(c=M^e mod N): ",enc)
    dec = decrypt(enc, d, N)
    #print ("RSA Decipher (c^d mod N): ",dec)
    return (enc, dec)

if __name__ == '__main__':
    test('5')
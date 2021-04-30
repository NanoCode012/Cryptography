import Crypto.Util.number
from pyasn1.type import univ, namedtype, tag

import sys
import util.pem as pem
try:
    from util.parser_c import int_to_bytes, bytes_to_int
except:
    from util.parser import int_to_bytes, bytes_to_int
    print('Importing parser.. Please run setup.py')


def encrypt(plain, e, N):
    return pow(plain, e, N)


def decrypt(cipher, d, N):
    return pow(cipher, d, N)


class PublicKey:
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.
        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder

        class AsnPubKey(univ.Sequence):
            """ASN.1 contents of DER encoded public key:
            RSAPublicKey ::= SEQUENCE {
                modulus           INTEGER,  -- n
                publicExponent    INTEGER,  -- e
            """
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("modulus", univ.Integer()),
                namedtype.NamedType("publicExponent", univ.Integer()),
            )

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)

        return encoder.encode(asn_key)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded public key file.
        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der(self.e, self.n)
        return pem.save_pem(der, "RSA PUBLIC KEY")


class RSA:
    def __init__(self, bits=1024):
        # assert bits in (1024,2048,3072,4096), 'bits need to be in 1024,2048,3072,4096'

        from math import log2
        assert log2(bits) % 1 == 0, 'Bits need to be a power of 2'
        assert (bits / 8) % 1 == 0, 'Bits need to be divisible of 8'
        self.bits = bits
        self.length = bits//8
        self._generate()

    def _generate(self):
        self.p = Crypto.Util.number.getPrime(
            self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.q = Crypto.Util.number.getPrime(
            self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.N = self.p * self.q
        self.PHI = (self.p-1)*(self.q-1)
        self.e = 65537 # Industry Standard (Has only 2 bits set)
        self.d = Crypto.Util.number.inverse(self.e, self.PHI)

        # for chinese remainder theorem
        self.dp = self.d % (self.p-1)
        self.dq = self.d % (self.q-1)
        self.qinv = Crypto.Util.number.inverse(self.q, self.p)

    def _pad(self, b: bytes, padding: str='OneAndZeroes'):
        if padding == 'OneAndZeroes':
            # https://crypto.stackexchange.com/questions/18171/how-to-find-which-padding-method-is-used-in-block-cipher-aes-encyption
            # Use 0x80 instead for byte level
            return b + bytes.fromhex('80') + bytes(self.length - len(b) -1)
        
        raise Exception('Padding not valid')

    def _pad_zeroes(self, arr: list, length: int):
        # Pad each block in front with zero if size < blocksize/length
        # zero = bytes_to_int(bytes.fromhex('00'))
        new_arr = arr.copy()
        for i in range(0, len(new_arr)):
            if len(new_arr[i]) < length:
                new_arr[i] = bytes(length - len(new_arr[i])) + new_arr[i]

        return new_arr

    def _unpad(self, b: bytes, padding: str='OneAndZeroes'):
        if padding == 'OneAndZeroes':
            one = bytes_to_int(bytes.fromhex('80'))

            for i in range(len(b)-1, 0, -1):
                # print(b[i])
                if (b[i] == 0): continue

                # Is not padded
                if (b[i] != one): return b

                # Is padded
                return b[:i]
        
        raise Exception('Padding not valid')

    def _split_bytes(self, b: bytes, length: int):
        return [b[i:i+length] for i in range(0, len(b), length)]

    def encrypt(self, message: bytes, padding='OneAndZeroes'):
        assert isinstance(message, bytes), 'M has to be bytes obj'

        length = self.bits // 8

        M_arr = self._split_bytes(message, length)

        # print(M_arr)
        
        # Pad
        if len(M_arr[-1]) < length:
            M_arr[-1] = self._pad(M_arr[-1], padding=padding)
        
        M_arr = [bytes_to_int(M) for M in M_arr]
        M_arr = [int_to_bytes(pow(M, self.e, self.N)) for M in M_arr]

        # return M_arr # test

        # Makes sure each block is length*2 bits before combine
        M_arr = self._pad_zeroes(M_arr, length*2)

        M_byte = bytearray()

        for M in M_arr:
            M_byte.extend(M)
            
        return bytes(M_byte)

    def decrypt(self, C, use_chinese_algo=True):
        # assert isinstance(C, bytes), 'C has to be bytes obj'
        
        length = self.length * 2
        # print(f'Length of c: {len(C)}')
        # print(f'Length: {length}')
        C_arr = self._split_bytes(C, length)
        # print(f'Length C_arr : {len(C_arr)}')
        # print(f'Length C_arr[0]: {len(C_arr[0])}')
        assert len(C) % length == 0, 'Not divisible'

        # Convert to int and decrypt block by block
        # C_arr = [int.from_bytes(c, byteorder='big') for c in C]
        C_arr = [int.from_bytes(c, byteorder='big') for c in C_arr]

        #Update to https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm (See next block)
        # C_arr = [int_to_bytes(pow(c, self.d, self.N)) for c in C_arr]
        
        # Assign list size first to reduce overhead with dynamic resizing
        C_arr_o = [None]*len(C_arr)
        if use_chinese_algo:
            for i, c in enumerate(C_arr):
                m1 = pow(c, self.dp, self.p)
                m2 = pow(c, self.dq, self.q)
                h = (self.qinv * (m1 - m2)) % self.p
                C_arr_o[i] = int_to_bytes((m2 + (h * self.q)) % self.N)
        else:
            for i, c in enumerate(C_arr):
                C_arr_o[i] = int_to_bytes(pow(c, self.d, self.N))

        # Special case block starts with \x00 but gets lost during decryption
        C_arr = self._pad_zeroes(C_arr_o, self.length)

        C_arr[-1] = self._unpad(C_arr[-1])

        # print(C_arr)

        C_byte = bytearray()

        for c in C_arr:
            C_byte.extend(c)

        return bytes(C_byte)



def test(message, bits=1024):

    #print ("No of bits in prime is ",bits)

    p = Crypto.Util.number.getPrime(
        bits, randfunc=Crypto.Random.get_random_bytes)
    #print ("\nRandom n-bit Prime (p): ",p)

    q = Crypto.Util.number.getPrime(
        bits, randfunc=Crypto.Random.get_random_bytes)
    #print ("\nRandom n-bit Prime (q): ",q)

    N = p*q

    #print ("\nN=p*q=",N)

    PHI = (p-1)*(q-1)

    #print ("\nPHI (p-1)(q-1)=",PHI)

    e = 65537
    #print ("\ne=",e)
    d = Crypto.Util.number.inverse(e, PHI)
    #print ("d=",d)

    #print ("\nCount of decimal digits (p): ",len(str(p)))
    #print ("Count of decimal digits (N): ",len(str(N)))

    # M=5

    # sample key 32 bytes
    # M=b'\xfa\x90\xd4\x00F\x92g\xcaA\x16\x05%\xb2H\xf9\x97\x9c\x1c\xe4\xc6\xcd\xf1\x9b\xe3/\x1b\x8c\x96\xb5Q\x8d\x8a'
    if isinstance(message, str):
        message = message.encode('utf-8')

    M = int.from_bytes(message, byteorder='big')
    #print ("\n\n=== Let's try these keys ==")
    #print ("\nRSA Message: ",M)
    enc = encrypt(M, e, N)
    #print ("RSA Cipher(c=M^e mod N): ",enc)
    dec = decrypt(enc, d, N)
    #print ("RSA Decipher (c^d mod N): ",dec)
    return (enc, dec)


if __name__ == '__main__':
    test('5')

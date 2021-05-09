import Crypto.Util.number
import sys
import os

from util.util import timing

try:
    from util.parser_c import int_to_bytes, bytes_to_int
except:
    from util.parser import int_to_bytes, bytes_to_int

    print("Importing parser.. Please run setup.py")

try:
    from util.prime_c import getPrime
except:
    from util.prime import getPrime

    print("Importing prime.. Please run setup.py")


class RSA:
    @timing
    def __init__(self, bits=1024, own_components=True, generate=True):
        # assert bits in (1024,2048,3072,4096), 'bits need to be in 1024,2048,3072,4096'

        from math import log2

        assert log2(bits) % 1 == 0, "Bits need to be a power of 2"
        assert (bits / 8) % 1 == 0, "Bits need to be divisible of 8"
        self.bits = bits
        self.length = bits // 8

        if generate:
            self._generate(own_components)

    def _generate(self, own_components):
        if own_components:
            self.p = getPrime(self.bits)
            self.q = getPrime(self.bits)
        else:
            self.p = Crypto.Util.number.getPrime(
                self.bits, randfunc=Crypto.Random.get_random_bytes
            )
            self.q = Crypto.Util.number.getPrime(
                self.bits, randfunc=Crypto.Random.get_random_bytes
            )

        self.N = self.p * self.q
        self.PHI = (self.p - 1) * (self.q - 1)
        self.e = 65537  # Industry Standard (Has only 2 bits set)
        if own_components:
            self.d = pow(self.e, -1, self.PHI)
        else:
            self.d = Crypto.Util.number.inverse(self.e, self.PHI)

        # for chinese remainder theorem
        self.dp = self.d % (self.p - 1)
        self.dq = self.d % (self.q - 1)
        if own_components:
            self.qinv = pow(self.q, -1, self.p)
        else:
            self.qinv = Crypto.Util.number.inverse(self.q, self.p)

    def _pad(self, b: bytes, length: int, padding: str = "OneAndZeroes"):
        if padding == "OneAndZeroes":
            # https://crypto.stackexchange.com/questions/18171/how-to-find-which-padding-method-is-used-in-block-cipher-aes-encyption
            # Use 0x80 instead for byte level
            return b + bytes.fromhex("80") + bytes(length - len(b) - 1)

        raise Exception("Padding not valid")

    def _pad_zeroes(self, arr: list, length: int):
        # Pad each block in front with zero if size < blocksize/length
        # zero = bytes_to_int(bytes.fromhex('00'))
        new_arr = arr.copy()
        for i in range(0, len(new_arr)):
            if len(new_arr[i]) < length:
                new_arr[i] = bytes(length - len(new_arr[i])) + new_arr[i]

        return new_arr

    def _unpad(self, b: bytes, padding: str = "OneAndZeroes"):
        if padding == "OneAndZeroes":
            one = bytes_to_int(bytes.fromhex("80"))

            for i in range(len(b) - 1, 0, -1):
                # print(b[i])
                if b[i] == 0:
                    continue

                # Is not padded
                if b[i] != one:
                    return b

                # Is padded
                return b[:i]

        raise Exception("Padding not valid")

    def _split_bytes(self, b: bytes, length: int):
        from math import ceil

        L = ceil(len(b) / length)
        res = [None] * L
        for i in range(0, L):
            res[i] = b[i * length : (i + 1) * length]

        return res

    def _join_blocks(self, arr):
        bytes_arr = bytearray()

        for b in arr:
            bytes_arr.extend(b)

        return bytes(bytes_arr)

    def save_pub_pem(self, path, file_name):
        from RSA.key import PublicKey

        pk = PublicKey(e=self.e, N=self.N)._save_pkcs1_pem()

        with open(os.path.join(path, file_name + ".pub"), "wb") as f:
            f.write(pk)

    def save_priv_pem(self, path, file_name):
        from RSA.key import PrivateKey

        pr = PrivateKey(
            e=self.e, N=self.N, d=self.d, p=self.p, q=self.q
        )._save_pkcs1_pem()

        with open(os.path.join(path, file_name), "wb") as f:
            f.write(pr)

    def save_pem(self, path, file_name):
        """
        Saves both public and private key
        """
        self.save_pub_pem(path, file_name)
        self.save_priv_pem(path, file_name)

    @classmethod
    def load_pub_pem(cls, path, file_name):
        from RSA.key import PublicKey

        with open(os.path.join(path, file_name), "rb") as f:
            pk_pem = f.read()

        pk = PublicKey._load_pkcs1_pem(pk_pem)

        # Convert bytes to bits and divide by 2
        # because N is 2x bit length
        bits = len(int_to_bytes(pk.__getstate__()[1])) * 8 // 2

        rsa_obj = cls(bits=bits, generate=False)
        (rsa_obj.e, rsa_obj.N) = pk.__getstate__()
        return rsa_obj

    @classmethod
    def load_priv_pem(cls, path, file_name):
        from RSA.key import PrivateKey

        with open(os.path.join(path, file_name), "rb") as f:
            pr_pem = f.read()

        pr = PrivateKey._load_pkcs1_pem(pr_pem)

        rsa_obj = cls(
            bits=len(int_to_bytes(pr.__getstate__()[1])) * 8 // 2, generate=False
        )

        (
            rsa_obj.e,
            rsa_obj.N,
            rsa_obj.d,
            rsa_obj.p,
            rsa_obj.q,
            rsa_obj.dp,
            rsa_obj.dq,
            rsa_obj.qinv,
        ) = pr.__getstate__()
        return rsa_obj

    @timing
    def encrypt(self, message: bytes, padding="OneAndZeroes"):
        assert isinstance(message, bytes), "M has to be bytes obj"

        length = self.bits // 8

        M_arr = self._split_bytes(message, length)

        # Pad
        if len(M_arr[-1]) < length:
            M_arr[-1] = self._pad(M_arr[-1], length=length, padding=padding)

        M_arr = [bytes_to_int(M) for M in M_arr]
        M_arr = [int_to_bytes(pow(M, self.e, self.N)) for M in M_arr]

        # Makes sure each block is length*2 bits before combine
        M_arr = self._pad_zeroes(M_arr, length * 2)

        return self._join_blocks(M_arr)

    @timing
    def decrypt(self, C, use_chinese_algo=True):
        # assert isinstance(C, bytes), 'C has to be bytes obj'

        length = self.length * 2
        C_arr = self._split_bytes(C, length)

        assert len(C) % length == 0, "Not divisible"

        # Convert to int and decrypt block by block
        C_arr = [int.from_bytes(c, byteorder="big") for c in C_arr]

        # https://stackoverflow.com/questions/5246856/how-did-python-implement-the-built-in-function-pow
        # https://github.com/python/cpython/blob/109fc2792a490ee5cd8a423e17d415fbdedec5c8/Objects/longobject.c#L4244-L4447

        # Update to https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm (See next block)
        # Assign list size first to reduce overhead with dynamic resizing
        C_arr_o = [None] * len(C_arr)
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

        # Unpad last block
        C_arr[-1] = self._unpad(C_arr[-1])

        return self._join_blocks(C_arr)


# https://asecuritysite.com/encryption/getprimen
@timing
def test(message, bits=1024):
    """
    This code is deprecated and should not be called. 
    This is only for testing RSA flow.
    """

    # print ("No of bits in prime is ",bits)

    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    # print ("\nRandom n-bit Prime (p): ",p)

    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    # print ("\nRandom n-bit Prime (q): ",q)

    N = p * q

    # print ("\nN=p*q=",N)

    PHI = (p - 1) * (q - 1)

    # print ("\nPHI (p-1)(q-1)=",PHI)

    e = 65537
    # print ("\ne=",e)
    d = Crypto.Util.number.inverse(e, PHI)
    # print ("d=",d)

    # print ("\nCount of decimal digits (p): ",len(str(p)))
    # print ("Count of decimal digits (N): ",len(str(N)))

    # M=5

    # sample key 32 bytes
    # M=b'\xfa\x90\xd4\x00F\x92g\xcaA\x16\x05%\xb2H\xf9\x97\x9c\x1c\xe4\xc6\xcd\xf1\x9b\xe3/\x1b\x8c\x96\xb5Q\x8d\x8a'
    if isinstance(message, str):
        message = message.encode("utf-8")

    M = int.from_bytes(message, byteorder="big")
    # print ("\n\n=== Let's try these keys ==")
    # print ("\nRSA Message: ",M)
    enc = pow(M, e, N)
    # print ("RSA Cipher(c=M^e mod N): ",enc)
    dec = pow(enc, d, N)
    # print ("RSA Decipher (c^d mod N): ",dec)
    return (enc, dec)


if __name__ == "__main__":
    test("5")


import unittest

import AES.aes as aes
import RSA.rsa as rsa
import os


class TestMix(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.data = b"YELLOW_SUBMARINE"

    def test_full(self):
        encrypted_bytes = aes.AES(self.key).encrypt_ctr(self.data, self.iv)
        decrypted_bytes = aes.AES(self.key).decrypt_ctr(encrypted_bytes, self.iv)

        rsa_obj = rsa.RSA(512)
        enc_key = rsa_obj.encrypt(self.iv + self.key)
        dec_key = rsa_obj.decrypt(enc_key)

        self.assertNotEqual(enc_key, dec_key)
        self.assertEqual(dec_key, self.iv + self.key)


def main():
    unittest.main(buffer=True)


if __name__ == "__main__":
    main()

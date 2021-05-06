import unittest

from util.parser import parse_input, int_to_bytes
import AES.aes as aes
import RSA.rsa as rsa
import os

from AES.tests import (
    TestBlock,
    TestKeySizes,
    TestCbc,
    TestPcbc,
    TestCfb,
    TestOfb,
    TestCtr,
    TestFunctions,
)


class TestRSA(unittest.TestCase):
    def setUp(self):
        self.rsa_obj = rsa.RSA(512)
        self.data = b"YELLOW_SUBMARINE"

    def tearDown(self):
        if os.path.exists(os.path.join("output", "temp")):
            os.remove(os.path.join("output", "temp"))

        if os.path.exists(os.path.join("output", "temp.pub")):
            os.remove(os.path.join("output", "temp.pub"))

    def test_encrypt(self):
        self.rsa_obj.encrypt(self.data)

    def test_decrypt(self):
        enc = self.rsa_obj.encrypt(self.data)
        dec = self.rsa_obj.decrypt(enc)

        self.assertNotEqual(enc, dec)
        self.assertEqual(self.data, dec)

    def test_save_pub(self):
        self.rsa_obj.save_pub_pem("output", "temp")

    def test_save_priv(self):
        self.rsa_obj.save_priv_pem("output", "temp")

    def test_load_pub(self):
        enc_real = self.rsa_obj.encrypt(self.data)
        self.rsa_obj.save_pub_pem("output", "temp")

        e, N, bits = self.rsa_obj.e, self.rsa_obj.N, self.rsa_obj.bits

        rsa_obj = rsa.RSA.load_pub_pem("output", "temp")
        enc_test = rsa_obj.encrypt(self.data)

        self.assertNotEqual(e, N)
        self.assertEqual(rsa_obj.e, e)
        self.assertEqual(rsa_obj.N, N)
        self.assertEqual(rsa_obj.bits, bits)

        # d should not be in pub key
        self.assertRaises(AttributeError, lambda: rsa_obj.d)

        self.assertEqual(len(enc_real), len(enc_test))
        self.assertEqual(enc_real, enc_test)

    def test_load_priv(self):
        enc = self.rsa_obj.encrypt(self.data)
        dec_real = self.rsa_obj.decrypt(enc)
        self.rsa_obj.save_priv_pem("output", "temp")

        e, N, bits = self.rsa_obj.e, self.rsa_obj.N, self.rsa_obj.bits

        rsa_obj = rsa.RSA.load_priv_pem("output", "temp")
        dec_test = rsa_obj.decrypt(enc)

        self.assertNotEqual(e, N)
        self.assertEqual(rsa_obj.e, e)
        self.assertEqual(rsa_obj.N, N)
        self.assertEqual(rsa_obj.bits, bits)

        self.assertEqual(len(dec_real), len(dec_test))
        self.assertEqual(dec_real, dec_test)

    def test_fail_load_pub_to_decrypt(self):
        enc = self.rsa_obj.encrypt(self.data)
        self.rsa_obj.save_pub_pem("output", "temp")
        rsa_obj = rsa.RSA.load_pub_pem("output", "temp")

        self.assertRaises(AttributeError, rsa_obj.decrypt, enc)


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

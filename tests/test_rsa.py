import unittest
import os

import RSA.rsa as rsa


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

        rsa_obj = rsa.RSA.load_pub_pem("output", "temp.pub")
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
        rsa_obj = rsa.RSA.load_pub_pem("output", "temp.pub")

        self.assertRaises(AttributeError, rsa_obj.decrypt, enc)

    def test_chinese_remainder(self):
        enc = self.rsa_obj.encrypt(self.data)
        dec = self.rsa_obj.decrypt(enc, use_chinese_algo=True)

        self.assertEqual(self.data, dec)

        dec = self.rsa_obj.decrypt(enc, use_chinese_algo=False)

        self.assertEqual(self.data, dec)

    def test_not_own_components(self):
        rsa_obj = rsa.RSA(bits=512, own_components=False)
        enc = rsa_obj.encrypt(self.data)
        dec = rsa_obj.decrypt(enc)

        self.assertEqual(self.data, dec)

    def test_keysize(self):
        rsa_obj_1024 = rsa.RSA(bits=1024)

        self.assertTrue(self.rsa_obj.N < rsa_obj_1024.N)
        self.assertTrue(self.rsa_obj.length < rsa_obj_1024.length)


def main():
    unittest.main(buffer=True)


if __name__ == "__main__":
    main()

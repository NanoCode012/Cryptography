import argparse
import os
import time

try:
    from util.parser_c import parse_input, int_to_bytes
except:
    from util.parser import parse_input, int_to_bytes

    print("Importing parser.. Please run setup.py")


try:
    import util.aes_c as aes
except:
    import util.aes as aes

    print("Importing aes.. Please run setup.py")

try:
    assert False
    import util.rsa_c as rsa
except:
    import util.rsa as rsa

    print("Importing rsa.. Please run setup.py")


def config_aes(opt):
    """
    Return (key, iv) for AES
    """
    if opt.key:
        key, _ = parse_input(opt.key)
    else:
        key = os.urandom(opt.aes_key_size)

    if opt.iv:
        iv, _ = parse_input(opt.iv)
    else:
        iv = os.urandom(16)

    return key, iv


def encrypt_aes(data, key, iv):
    return aes.AES(key).encrypt_ctr(data, iv)


def decrypt_aes(cipher, key, iv):
    return aes.AES(key).decrypt_ctr(cipher, iv)


def encrypt_rsa(data, e, N):
    assert isinstance(data, bytes), "Data is not of type bytes"

    return rsa.encrypt(int.from_bytes(data, byteorder="big"), e, N)


def decrypt_rsa(cipher, d, N):
    assert isinstance(cipher, int), "Data is not of type int"

    return rsa.decrypt(cipher, d, N)


def output(opt, data, out=None):
    if opt.show:
        print(data)

    if out and isinstance(out, str):
        output_file = out
    elif input_type == "text":
        output_file = opt.output if opt.output else os.path.join("output", "output.txt")
    elif input_type == "file":
        output_file = (
            opt.output
            if opt.output
            else os.path.join("output", os.path.basename(opt.input))
        )

    with open(output_file, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--task", type=str, default="test_rsa", help="encrypt, decrypt, test"
    )
    parser.add_argument(
        "--input", type=str, default="file.txt", help="text or path to file"
    )
    parser.add_argument("--output", type=str, default=None, help="output path")
    parser.add_argument(
        "--aes-key-size", type=int, default=16, help="AES key size in bytes"
    )
    parser.add_argument(
        "--rsa-key-size", type=int, default=1024, help="RSA key size in bytes"
    )
    parser.add_argument("--show", action="store_true", help="output to console")
    parser.add_argument("--key", type=str, default=None, help="AES key path in bytes")
    parser.add_argument("--iv", type=str, default=None, help="AES iv path in bytes")
    parser.add_argument("--rsa", action="store_true", help="use rsa to encrypt")
    opt = parser.parse_args()

    data, input_type = parse_input(opt.input)

    if not os.path.exists("output"):
        os.mkdir("output")

    if opt.task == "encrypt_aes":
        key, iv = config_aes(opt)
        encrypted_bytes = encrypt_aes(data, key, iv)

        output(opt, encrypted_bytes)

        output(opt, key, out="output/key.txt")
        output(opt, iv, out="output/iv.txt")

    elif opt.task == "decrypt_aes":
        key, iv = config_aes(opt)
        decrypted_bytes = decrypt_aes(data, key, iv)

        output(opt, decrypted_bytes)

    elif opt.task == "test":
        key, iv = config_aes(opt)
        start = time.time()
        encrypted_bytes = encrypt_aes(data, key, iv)
        print(f"Encrypting took: {time.time() - start} sec")

        output(opt, encrypted_bytes, out="output/test.encrypted")

        start = time.time()
        decrypted_bytes = decrypt_aes(encrypted_bytes, key, iv)
        print(f"Decrypting took: {time.time() - start} sec")

        output(opt, decrypted_bytes, out="output/test.decrypted")

        # Encrypt (iv, key)
        start = time.time()
        enc, dec = rsa.test(iv + key)
        print(f"RSA test everything took: {time.time() - start} sec")

        assert (
            dec.to_bytes(16 + opt.aes_key_size, byteorder="big") == iv + key
        ), "Key is not the same as the decrypted value"

        enc = enc.to_bytes((enc.bit_length() + 7) // 8, byteorder="big")
        dec = dec.to_bytes((dec.bit_length() + 7) // 8, byteorder="big")

        output(opt, enc, out="output/key.encrypted")
        output(opt, dec, out="output/key.decrypted")
    elif opt.task == "test_rsa":
        rsa_obj = rsa.RSA(opt.rsa_key_size)
        # Crypto lib takes 0.3s -> 1.1s for 1024bits

        enc = rsa_obj.encrypt(data)

        dec = rsa_obj.decrypt(enc, use_chinese_algo=True)
        # 49s for custom pow

        assert len(data) == len(dec), f"Length not equal! {len(data)} vs {len(dec)}"

        assert data == dec, "Data and decrypted are not equal!"

        rsa_obj.save_pub_pem("output", "key")

        output(opt, enc, out="output/file.encrypted")
        output(opt, dec, out="output/file.decrypted")

        print("Test successful: RSA encryption + decryption")
    elif opt.task == "test_load_rsa_pub":
        # create a real encryption
        rsa_obj = rsa.RSA(opt.rsa_key_size)
        enc_real = rsa_obj.encrypt(data)
        rsa_obj.save_pub_pem("output", "key")

        e, N, bits = rsa_obj.e, rsa_obj.N, rsa_obj.bits

        # load public key
        rsa_obj = rsa.RSA.load_pub_pem("output", "key")
        enc_test = rsa_obj.encrypt(data)

        assert rsa_obj.e == e, f"Different e {rsa_obj.e} vs {e}"
        assert rsa_obj.N == N, f"Different N {rsa_obj.N} vs {N}"
        assert rsa_obj.bits == bits, f"Different bits {rsa_obj.bits} vs {bits}"

        assert len(enc_real) == len(
            enc_test
        ), f"Length not equal! {len(enc_real)} vs {len(enc_test)}"
        assert enc_real == enc_test, "Encrypted real and Encrypted test are not equal!"

        output(opt, enc_real, out="output/enc_real.encrypted")
        output(opt, enc_test, out="output/enc_test.encrypted")

        print("Test successful: Load RSA from PUBLIC key and encrypt match")

    elif opt.task == "test_load_rsa_priv":
        # create a real encryption
        rsa_obj = rsa.RSA(opt.rsa_key_size)
        enc = rsa_obj.encrypt(data)
        dec_real = rsa_obj.decrypt(enc)
        rsa_obj.save_priv_pem("output", "key")

        e, N, bits = rsa_obj.e, rsa_obj.N, rsa_obj.bits

        # load public key
        rsa_obj = rsa.RSA.load_priv_pem("output", "key")
        dec_test = rsa_obj.decrypt(enc)

        assert rsa_obj.e == e, f"Different e {rsa_obj.e} vs {e}"
        assert rsa_obj.N == N, f"Different N {rsa_obj.N} vs {N}"
        assert rsa_obj.bits == bits, f"Different bits {rsa_obj.bits} vs {bits}"

        assert len(dec_real) == len(
            dec_test
        ), f"Length not equal! {len(dec_real)} vs {len(dec_test)}"
        assert dec_real == dec_test, "Decrypted real and Decrypted test are not equal!"

        output(opt, dec_real, out="output/dec_real.decrypted")
        output(opt, dec_test, out="output/dec_test.decrypted")

        print("Test successful: Load RSA from PRIVATE key and decrypt match")


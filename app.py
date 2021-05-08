import argparse
import os
import time

from util.util import timing

try:
    from util.parser_c import parse_input, int_to_bytes
except:
    from util.parser import parse_input, int_to_bytes

    print("Importing parser.. Please run setup.py")


try:
    import AES.aes_c as aes
except:
    import AES.aes as aes

    print("Importing aes.. Please run setup.py")

try:
    # assert False
    import RSA.rsa_c as rsa
except:
    import RSA.rsa as rsa

    print("Importing rsa.. Please run setup.py")


def config_aes(opt):
    """
    Return (key, iv) for AES
    """
    if opt.aes_key:
        key, _ = parse_input(opt.aes_key)
    else:
        key = os.urandom(opt.aes_key_size)

    if opt.aes_iv:
        iv, _ = parse_input(opt.aes_iv)
    else:
        iv = os.urandom(16)

    return key, iv


def config_rsa(opt):
    """
    Return a RSA object based on arguments passed
     - A full RSA object if a private PEM given
     - A partial RSA object if a public PEM given
     - A new RSA object if does not satisfy the above
    """
    if opt.rsa_priv:
        opt.passed_key = True
        path, name = os.path.split(opt.rsa_priv)
        return rsa.RSA.load_priv_pem(path, name)

    if opt.rsa_pub:
        opt.passed_key = True
        path, name = os.path.split(opt.rsa_pub)
        return rsa.RSA.load_pub_pem(path, name)

    return rsa.RSA(opt.rsa_key_size)


@timing
def encrypt_aes(data, key, iv):
    return aes.AES(key).encrypt_ctr(data, iv)


@timing
def decrypt_aes(cipher, key, iv):
    return aes.AES(key).decrypt_ctr(cipher, iv)


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
    else:
        raise Exception("Output path is not valid")

    with open(output_file, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # BASE arguments
    parser.add_argument(
        "--task", type=str, default="test_rsa", help="See below if else block"
    )
    parser.add_argument(
        "--input", type=str, default="file.txt", help="text or path to file"
    )
    parser.add_argument("--output", type=str, default=None, help="output path")
    parser.add_argument("--show", action="store_true", help="output to console")

    # AES arguments
    parser.add_argument(
        "--aes-key-size", type=int, default=16, help="AES key size in bytes"
    )
    parser.add_argument("--aes-key", type=str, default=None, help="AES key path")
    parser.add_argument("--aes-iv", type=str, default=None, help="AES iv path")

    # RSA arguments
    parser.add_argument(
        "--rsa-key-size", type=int, default=1024, help="RSA key size in bytes"
    )
    parser.add_argument(
        "--rsa-pub", type=str, default=None, help="RSA public key path in PEM format",
    )
    parser.add_argument(
        "--rsa-priv", type=str, default=None, help="RSA private key path in PEM format"
    )

    opt = parser.parse_args()

    data, input_type = parse_input(opt.input)

    if not os.path.exists("output"):
        os.mkdir("output")

    if opt.task == "encrypt_aes":
        key, iv = config_aes(opt)
        encrypted_bytes = encrypt_aes(data, key, iv)

        output(opt, encrypted_bytes, out="output/file.encrypted")

        output(opt, key, out="output/key.txt")
        output(opt, iv, out="output/iv.txt")

    elif opt.task == "decrypt_aes":
        key, iv = config_aes(opt)
        decrypted_bytes = decrypt_aes(data, key, iv)

        output(opt, decrypted_bytes, out="output/file.decrypted")

    elif opt.task == "encrypt_rsa":
        rsa_obj = config_rsa(opt)

        enc = rsa_obj.encrypt(data)

        if not hasattr(opt, "passed_key"):
            rsa_obj.save_pem("output", "key")

        output(opt, enc, out="output/file.encrypted")

    elif opt.task == "decrypt_rsa":
        rsa_obj = config_rsa(opt)

        assert hasattr(rsa_obj, "d"), "RSA object does not have decrypt key"
        dec = rsa_obj.decrypt(data)

        output(opt, dec, out="output/file.decrypted")

    elif opt.task == "test":
        key, iv = config_aes(opt)
        encrypted_bytes = encrypt_aes(data, key, iv)
        decrypted_bytes = decrypt_aes(encrypted_bytes, key, iv)

        assert data == decrypted_bytes, "Data is not the same as decrypted value"

        rsa_obj = config_rsa(opt)

        # Encrypt (iv, key)
        enc_key = rsa_obj.encrypt(iv + key)
        dec_key = rsa_obj.decrypt(enc_key)

        assert dec_key == iv + key, "Decrypted key is not the same as key+iv"

        output(opt, encrypted_bytes, out="output/file.encrypted")
        output(opt, decrypted_bytes, out="output/file.decrypted")

        rsa_obj.save_pem("output", "key")

        print(
            "Test successful: AES encryption + decryption of file AND RSA encryption + decryption of keys"
        )
    elif opt.task == "test_aes":
        key, iv = config_aes(opt)
        encrypted_bytes = encrypt_aes(data, key, iv)
        decrypted_bytes = decrypt_aes(encrypted_bytes, key, iv)

        assert data == decrypted_bytes, "Data is not the same as decrypted value"

        output(opt, encrypted_bytes, out="output/file.encrypted")
        output(opt, decrypted_bytes, out="output/file.decrypted")

        output(opt, key, out="output/key.txt")
        output(opt, iv, out="output/iv.txt")

        print("Test successful: AES encryption + decryption of file")

    elif opt.task == "test_rsa":
        rsa_obj = config_rsa(opt)
        # Crypto lib takes 0.3s -> 1.1s for 1024bits

        enc = rsa_obj.encrypt(data)

        dec = rsa_obj.decrypt(enc, use_chinese_algo=True)
        # 49s for custom pow

        assert len(data) == len(dec), f"Length not equal! {len(data)} vs {len(dec)}"

        assert data == dec, "Data and decrypted are not equal!"

        rsa_obj.save_pem("output", "key")

        output(opt, enc, out="output/file.encrypted")
        output(opt, dec, out="output/file.decrypted")

        print("Test successful: RSA encryption + decryption")
    elif opt.task == "test_load_rsa_pub":
        # create a real encryption
        rsa_obj = config_rsa(opt)
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
        rsa_obj = config_rsa(opt)
        enc = rsa_obj.encrypt(data)
        dec_real = rsa_obj.decrypt(enc)
        rsa_obj.save_priv_pem("output", "key")

        e, N, bits = rsa_obj.e, rsa_obj.N, rsa_obj.bits

        # load private key
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


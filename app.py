import argparse
import os
import time
import timeit

try:
    import util.aes_c as aes
except:
    import util.aes as aes
    print('Importing aes.. Please run setup.py')

try:
    import util.rsa_c as rsa
except:
    import util.rsa as rsa
    print('Importing rsa.. Please run setup.py')

def parse_input(input):
    if os.path.exists(input): return (parse_file(input), 'file')

    return (input.encode('utf-8'), 'text')

def parse_file(file):
    with open(file, 'rb') as f:
        data = f.read()
    return data

def encrypt_aes(data, key, iv):
    return aes.AES(key).encrypt_ctr(data, iv)

def decrypt_aes(cipher, key, iv):
    return aes.AES(key).decrypt_ctr(cipher, iv)

def encrypt_rsa(data, e, N):
    assert isinstance(data, bytes), 'Data is not of type bytes'

    return rsa.encrypt(int.from_bytes(data, byteorder='big'), e, N)

def decrypt_rsa(cipher, d, N):
    assert isinstance(cipher, int), 'Data is not of type int'

    return rsa.decrypt(cipher, d, N)

def output(opt, data, out=None):
    if opt.show:
        print(data)

    if out and isinstance(out, str):
        output_file = out
    elif input_type == 'text':
        output_file = opt.output if opt.output else os.path.join('output', 'output.txt')
    elif input_type == 'file':
        output_file = opt.output if opt.output else os.path.join('output', os.path.basename(opt.input))

    with open(output_file, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--task', type=str, default='encrypt', help='encrypt, decrypt, test')
    parser.add_argument('--input', type=str, default='file.txt', help='text or path to file')
    parser.add_argument('--output', type=str, default=None, help='output path')
    parser.add_argument('--key-size', type=int, default=16, help='key size in bytes')
    parser.add_argument('--show', action='store_true', help='output to console')
    parser.add_argument('--key', type=str, default=None, help='key path in bytes')
    parser.add_argument('--iv', type=str, default=None, help='iv path in bytes')
    parser.add_argument('--rsa', action='store_true', help='use rsa to encrypt')
    opt = parser.parse_args()
    
    if opt.key:
        with open(opt.key, 'rb') as f:
            key = f.read()
    else:
        key = os.urandom(opt.key_size)

    if opt.iv:
        with open(opt.iv, 'rb') as f:
            iv = f.read()
    else:
        iv = os.urandom(16)
    
    data, input_type = parse_input(opt.input)

    if not os.path.exists('output'):
        os.mkdir('output')

    if (opt.task == 'encrypt'):
        encrypted_bytes = encrypt_aes(data, key, iv)

        output(opt, encrypted_bytes)

        with open('output/key.txt', 'wb') as f:
            f.write(key)

        with open('output/iv.txt', 'wb') as f:
            f.write(iv)

    elif (opt.task == 'decrypt'):
        decrypted_bytes = decrypt_aes(data, key, iv)

        output(opt, decrypted_bytes)

    elif (opt.task == 'test'):
        start = time.time()
        encrypted_bytes = encrypt_aes(data, key, iv)
        print(f'Encrypting took: {time.time() - start} sec')

        output(opt, encrypted_bytes, out='output/test.encrypted')

        start = time.time()
        decrypted_bytes = decrypt_aes(encrypted_bytes, key, iv)
        print(f'Decrypting took: {time.time() - start} sec')

        output(opt, decrypted_bytes, out='output/test.decrypted')

        # Encrypt (iv, key)
        start = time.time()
        enc, dec = rsa.test(iv + key)
        print(f'RSA test everything took: {time.time() - start} sec')

        # Sample e,d,N
        # start = time.time()
        # enc = encrypt_rsa(iv + key, 65537, 21879504801587652898858167460888405742804451521147521456003848352094635789498939169518658268566389839414765211718137676365482786331627700007313431455658608268502577004060128016035443843363883344224522580726098536122749843985137016996578381912076909604333564731149460224570264484537723552609989449932522515313055358061096927176568531628237679192085124917291845444949860351328391410599961588321500284264796285922221224970922429563781497239212573614820601531278515315578701354591802149380940325882290796138972092793643001634449308124352768317596045508762383083064003615703800781906184083399397968951460467474136704152443)
        # print(f'RSA encrypt took: {time.time() - start} sec')

        # start = time.time()
        # dec = decrypt_rsa(enc, 8977217207298045172197325526394086247829648922038800249507049181192681330845575388991817154305967968962006752568788960701097580366166728003977267373280131472908956705970319702628943725651995409100163452640871410597688989498456358805529589233803013553573241918620153278891228038958441587647933477404909141961944888818783079998752599607694618968986706021085244932910385066626238069944073070695995718097587875248636806905331433666941949076032958155970366220926052114592952933010180213787017504319157478287195840785678481897754601144120902159926628979446814361504337734032434941403123605747786558346701815420671162106273, 21879504801587652898858167460888405742804451521147521456003848352094635789498939169518658268566389839414765211718137676365482786331627700007313431455658608268502577004060128016035443843363883344224522580726098536122749843985137016996578381912076909604333564731149460224570264484537723552609989449932522515313055358061096927176568531628237679192085124917291845444949860351328391410599961588321500284264796285922221224970922429563781497239212573614820601531278515315578701354591802149380940325882290796138972092793643001634449308124352768317596045508762383083064003615703800781906184083399397968951460467474136704152443)
        # print(f'RSA decrypt took: {time.time() - start} sec')

        assert dec.to_bytes(16 + opt.key_size, byteorder='big') == iv + key, 'Key is not the same as the decrypted value'

        enc = enc.to_bytes((enc.bit_length() + 7) // 8, byteorder='big')
        dec = dec.to_bytes((dec.bit_length() + 7) // 8, byteorder='big')

        output(opt, enc, out='output/key.encrypted')
        output(opt, dec, out='output/key.decrypted')
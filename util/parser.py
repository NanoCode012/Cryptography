import os

def parse_input(input):
    if os.path.exists(input): return (parse_file(input), 'file')

    return (input.encode('utf-8'), 'text')

def parse_file(file):
    with open(file, 'rb') as f:
        data = f.read()
    return data

def int_to_bytes(num: int):
    return num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(b: bytes):
    return int.from_bytes(b, byteorder='big')
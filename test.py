import unittest

from tests.test_aes import *
from tests.test_rsa import *
from tests.test_prime import *
from tests.test_mix import *


def main():
    unittest.main(buffer=True)


if __name__ == "__main__":
    main()

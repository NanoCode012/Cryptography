# Adapted from https://github.com/sybrenstuvel/python-rsa/blob/main/rsa/key.py

from pyasn1.type import univ, namedtype, tag
import util.RSA.pem as pem


class PublicKey:
    def __init__(self, N: int, e: int) -> None:
        self.N = N
        self.e = e

    def __repr__(self) -> str:
        return "PublicKey(%i, %i)" % (self.e, self.N)

    def __getstate__(self) -> [int, int]:
        """Returns the key as tuple for pickling."""
        return self.e, self.N

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.
        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from util.RSA.asn1 import AsnPubKey

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName("modulus", self.N)
        asn_key.setComponentByName("publicExponent", self.e)

        return encoder.encode(asn_key)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded public key file.
        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return pem.save_pem(der, "RSA PUBLIC KEY")

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PublicKey":
        """Loads a key in PKCS#1 DER format.
        :param keyfile: contents of a DER-encoded file that contains the public
            key.
        :return: a PublicKey object
        First let's construct a DER encoded key:
        >>> import base64
        >>> b64der = 'MAwCBQCNGmYtAgMBAAE='
        >>> der = base64.standard_b64decode(b64der)
        This loads the file:
        >>> PublicKey._load_pkcs1_der(der)
        PublicKey(2367317549, 65537)
        """

        from pyasn1.codec.der import decoder
        from util.RSA.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(N=int(priv["modulus"]), e=int(priv["publicExponent"]))

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1 PEM-encoded public key file.
        The contents of the file before the "-----BEGIN RSA PUBLIC KEY-----" and
        after the "-----END RSA PUBLIC KEY-----" lines is ignored.
        :param keyfile: contents of a PEM-encoded file that contains the public
            key.
        :return: a PublicKey object
        """

        der = pem.load_pem(keyfile, "RSA PUBLIC KEY")
        return cls._load_pkcs1_der(der)


class PrivateKey:
    def __init__(self, N: int, e: int, d: int, p: int, q: int) -> None:
        self.N = N
        self.e = e
        self.d = d
        self.p = p
        self.q = q

        # Calculate exponents and coefficient.
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = pow(q, -1, p)

    def __repr__(self) -> str:
        return "PrivateKey(%i, %i, %i, %i, %i)" % (
            self.e,
            self.N,
            self.d,
            self.p,
            self.q,
        )

    def __getstate__(self) -> [int, int, int, int, int, int, int, int]:
        """Returns the key as tuple for pickling."""
        return self.e, self.N, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PrivateKey":
        """Loads a key in PKCS#1 DER format.
        :param keyfile: contents of a DER-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object
        First let's construct a DER encoded key:
        >>> import base64
        >>> b64der = 'MC4CAQACBQDeKYlRAgMBAAECBQDHn4npAgMA/icCAwDfxwIDANcXAgInbwIDAMZt'
        >>> der = base64.standard_b64decode(b64der)
        This loads the file:
        >>> PrivateKey._load_pkcs1_der(der)
        PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)
        """

        from pyasn1.codec.der import decoder

        (priv, _) = decoder.decode(keyfile)

        if priv[0] != 0:
            raise ValueError("Unable to read this file, version %s != 0" % priv[0])

        as_ints = map(int, priv[1:6])
        key = cls(*as_ints)

        exp1, exp2, coef = map(int, priv[6:9])

        if (key.exp1, key.exp2, key.coef) != (exp1, exp2, coef):
            raise Exception(
                "You have provided a malformed keyfile. Either the exponents "
                "or the coefficient are incorrect. Using the correct values "
                "instead.",
                UserWarning,
            )

        return key

    def _save_pkcs1_der(self) -> bytes:
        """Saves the private key in PKCS#1 DER format.
        :returns: the DER-encoded private key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from util.RSA.asn1 import AsnPrivKey

        # Create the ASN object
        asn_key = AsnPrivKey()
        asn_key.setComponentByName("version", 0)
        asn_key.setComponentByName("modulus", self.N)
        asn_key.setComponentByName("publicExponent", self.e)
        asn_key.setComponentByName("privateExponent", self.d)
        asn_key.setComponentByName("prime1", self.p)
        asn_key.setComponentByName("prime2", self.q)
        asn_key.setComponentByName("exponent1", self.exp1)
        asn_key.setComponentByName("exponent2", self.exp2)
        asn_key.setComponentByName("coefficient", self.coef)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PrivateKey":
        """Loads a PKCS#1 PEM-encoded private key file.
        The contents of the file before the "-----BEGIN RSA PRIVATE KEY-----" and
        after the "-----END RSA PRIVATE KEY-----" lines is ignored.
        :param keyfile: contents of a PEM-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object
        """

        der = pem.load_pem(keyfile, b"RSA PRIVATE KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded private key file.
        :return: contents of a PEM-encoded file that contains the private key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return pem.save_pem(der, b"RSA PRIVATE KEY")


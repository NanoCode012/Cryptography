from pyasn1.type import univ, namedtype, tag
import util.RSA.pem as pem


class AsnPubKey(univ.Sequence):
    """ASN.1 contents of DER encoded public key:
            RSAPublicKey ::= SEQUENCE {
                modulus           INTEGER,  -- n
                publicExponent    INTEGER,  -- e
            """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
    )


class PublicKey:
    def __init__(self, N: int, e: int) -> None:
        self.N = N
        self.e = e

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.
        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder

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


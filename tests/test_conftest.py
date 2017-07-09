from __future__ import absolute_import, division, unicode_literals

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .conftest import KeyCache


def test_keycache_generates_keys():
    k = KeyCache([])
    assert isinstance(k.generate_rsa_key(), rsa.RSAPrivateKey)
    assert isinstance(
        k.generate_ec_key(ec.SECP256R1()), ec.EllipticCurvePrivateKey
    )
    assert isinstance(k.generate_dsa_key(), dsa.DSAPrivateKey)

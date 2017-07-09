from __future__ import absolute_import, division, unicode_literals

from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .conftest import KeyCache


def test_keycache_generates_rsa_key():
    k = KeyCache([])
    assert isinstance(k.generate_rsa_key(key_size=512), rsa.RSAPrivateKey)


def test_keycache_generates_ec_key():
    k = KeyCache([])
    assert isinstance(
        k.generate_ec_key(ec.SECP256R1()), ec.EllipticCurvePrivateKey
    )


def test_keycache_generates_dsa_key():
    k = KeyCache([])
    assert isinstance(k.generate_dsa_key(key_size=1024), dsa.DSAPrivateKey)

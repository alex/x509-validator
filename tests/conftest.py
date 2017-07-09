from __future__ import absolute_import, division, unicode_literals

import base64
import datetime
import hashlib
import threading
from collections import defaultdict

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

import pytest

import wsgiref.simple_server

from validator import (
    ANY_EXTENDED_KEY_USAGE_OID, X509Validator, ValidationContext,
    ValidationError
)

from .utils import create_ca_issuer, create_extension


class KeyCache(object):
    def __init__(self, keys):
        self._inuse_keys = defaultdict(list)
        self._free_keys = defaultdict(list, keys)

    @classmethod
    def _from_dump(cls, cached_entries):
        keys = defaultdict(list)
        for entry in cached_entries:
            params = tuple(entry["params"])
            for key in entry["keys"]:
                key = serialization.load_der_private_key(
                    base64.b64decode(key),
                    password=None,
                    backend=default_backend(),
                )
                keys[params].append(key)
        return cls(keys)

    def _dump(self):
        cache_entries = []
        for (params, keys) in self._free_keys.items():
            cache_entries.append({
                "params": params,
                "keys": [
                    base64.b64encode(key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()
                    )).decode("ascii")
                    for key in keys
                ],
            })
        return cache_entries

    def _generate_key(self, params, create_key):
        if self._free_keys[params]:
            key = self._free_keys[params].pop()
        else:
            key = create_key()
        self._inuse_keys[params].append(key)
        return key

    def generate_rsa_key(self, public_exponent=65537, key_size=2048):
        return self._generate_key(
            ("rsa", public_exponent, key_size),
            lambda: rsa.generate_private_key(
                public_exponent, key_size, backend=default_backend()
            )
        )

    def generate_ec_key(self, curve):
        return self._generate_key(
            ("ecdsa", curve.name),
            lambda: ec.generate_private_key(curve, backend=default_backend()),
        )

    def generate_dsa_key(self):
        return self._generate_key(
            ("dsa",),
            lambda: dsa.generate_private_key(2048, backend=default_backend())
        )

    def _reset(self):
        for params, keys in self._inuse_keys.items():
            self._free_keys[params].extend(keys)
        self._inuse_keys.clear()


@pytest.fixture(scope="session")
def key_cache(request):
    keys = request.config.cache.get("x509-validator/keys", [])
    key_cache = KeyCache._from_dump(keys)
    try:
        yield key_cache
    finally:
        request.config.cache.set("x509-validator/keys", key_cache._dump())


class CertificatePair(object):
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key


class CAWorkspace(object):
    def __init__(self, key_cache):
        self._key_cache = key_cache
        self._roots = []

    def _build_validator(self):
        return X509Validator(self._roots)

    def _build_validation_context(self, name=x509.DNSName("example.com"),
                                  extra_certs=[], extended_key_usage=None):
        if extended_key_usage is None:
            extended_key_usage = ANY_EXTENDED_KEY_USAGE_OID
        return ValidationContext(
            name=name,
            extra_certs=[c.cert for c in extra_certs],
            extended_key_usage=extended_key_usage,
        )

    def assert_doesnt_validate(self, cert, **kwargs):
        validator = self._build_validator()
        ctx = self._build_validation_context(**kwargs)
        with pytest.raises(ValidationError):
            validator.validate(cert.cert, ctx)

    def assert_validates(self, cert, expected_chain, **kwargs):
        validator = self._build_validator()
        chain = validator.validate(
            cert.cert, self._build_validation_context(**kwargs)
        )
        assert chain == [c.cert for c in expected_chain]

    def _issue_new_cert(self, key=None, names=[x509.DNSName("example.com")],
                        issuer=None, not_valid_before=None,
                        not_valid_after=None, signature_hash_algorithm=None,
                        extended_key_usages=[ANY_EXTENDED_KEY_USAGE_OID],
                        ca_issuers=None,
                        extra_extensions=[]):

        if key is None:
            key = self._key_cache.generate_rsa_key()

        subject_name = x509.Name([])

        if issuer is not None:
            issuer_name = issuer.cert.subject
            ca_key = issuer.key
        else:
            issuer_name = subject_name
            ca_key = key

        if not_valid_before is None:
            not_valid_before = datetime.datetime.utcnow()
        if not_valid_after is None:
            not_valid_after = (
                datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            )

        if signature_hash_algorithm is None:
            signature_hash_algorithm = hashes.SHA256()

        builder = x509.CertificateBuilder().serial_number(
            1
        ).public_key(
            key.public_key()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).subject_name(
            subject_name
        ).issuer_name(
            issuer_name
        )
        if names is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(names),
                critical=False,
            )
        if extended_key_usages is not None:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(extended_key_usages),
                critical=False,
            )
        if ca_issuers is not None:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(ca_issuers),
                critical=False,
            )
        for ext in extra_extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)
        cert = builder.sign(
            ca_key, signature_hash_algorithm, default_backend()
        )
        return CertificatePair(cert, key)

    def _issue_new_ca(self, issuer=None, path_length=None, **kwargs):
        return self._issue_new_cert(
            issuer=issuer,
            extra_extensions=[
                create_extension(
                    x509.BasicConstraints(
                        ca=True, path_length=path_length
                    ),
                    critical=True
                )
            ] + kwargs.pop("extra_extensions", []),
            **kwargs
        )

    def add_trusted_root(self, cert):
        self._roots.append(cert.cert)

    def issue_new_trusted_root(self, **kwargs):
        certpair = self._issue_new_ca(**kwargs)
        self.add_trusted_root(certpair)
        return certpair

    def issue_new_ca(self, ca, **kwargs):
        return self._issue_new_ca(issuer=ca, **kwargs)

    def issue_new_leaf(self, ca, **kwargs):
        return self._issue_new_cert(issuer=ca, **kwargs)

    def issue_new_self_signed(self, **kwargs):
        return self._issue_new_cert(**kwargs)


@pytest.fixture
def ca_workspace(key_cache):
    workspace = CAWorkspace(key_cache)
    try:
        yield workspace
    finally:
        key_cache._reset()


class WSGIApplication(object):
    def __init__(self):
        self.urls = {}

    def __call__(self, environ, start_response):
        try:
            contents = self.urls[environ["PATH_INFO"]]
        except KeyError:
            start_response(b"404 Not Found", [])
            return []
        start_response(
            b"200 OK", [(b"Content-Type", b"application/pkix-cert")]
        )
        return [contents]


class Server(object):
    def __init__(self, wsgi_app, server_address):
        self.wsgi_app = wsgi_app
        self.server_address = server_address

    @property
    def base_url(self):
        (host, port) = self.server_address
        return "http://{}:{}".format(host, port)

    def create_aia_url(self, cert):
        if isinstance(cert, CertificatePair):
            data = cert.cert.public_bytes(serialization.Encoding.DER)
        else:
            data = cert
        url = "/{}.crt".format(hashlib.sha256(data).hexdigest())
        self.wsgi_app.urls[url] = data
        return create_ca_issuer("{}{}".format(self.base_url, url))


@pytest.fixture
def server():
    wsgi_app = WSGIApplication()
    httpd = wsgiref.simple_server.make_server("localhost", 0, wsgi_app)
    t = threading.Thread(
        # The default poll_interval means that shutdown takes half a second
        target=httpd.serve_forever, kwargs={"poll_interval": 0}
    )
    t.start()
    yield Server(wsgi_app, httpd.server_address)
    httpd.shutdown()
    t.join()

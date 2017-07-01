from __future__ import absolute_import, division, unicode_literals

import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import pytest

from validator import (
    ANY_EXTENDED_KEY_USAGE_OID, X509Validator, ValidationError,
    ValidationContext
)


class CertificatePair(object):
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key


class CAWorkspace(object):
    def __init__(self, key_cache):
        self._key_cache = key_cache
        self._roots = []

    def build_validator(self):
        return X509Validator(self._roots)

    def build_validation_context(self, name=x509.DNSName("example.com"),
                                 extra_certs=[], extended_key_usage=None):
        if extended_key_usage is None:
            extended_key_usage = ANY_EXTENDED_KEY_USAGE_OID
        return ValidationContext(
            name=name,
            extra_certs=[c.cert for c in extra_certs],
            extended_key_usage=extended_key_usage,
        )

    def assert_doesnt_validate(self, cert, **kwargs):
        validator = self.build_validator()
        ctx = self.build_validation_context(**kwargs)
        with pytest.raises(ValidationError):
            validator.validate(cert.cert, ctx)

    def assert_validates(self, cert, expected_chain, **kwargs):
        validator = self.build_validator()
        chain = validator.validate(
            cert.cert, self.build_validation_context(**kwargs)
        )
        assert chain == [c.cert for c in expected_chain]

    def _issue_new_cert(self, key=None, names=[x509.DNSName("example.com")],
                        issuer=None, not_valid_before=None,
                        not_valid_after=None, signature_hash_algorithm=None,
                        extended_key_usages=[ANY_EXTENDED_KEY_USAGE_OID],
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

    def issue_new_ca_certificate(self, ca, **kwargs):
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
        key_cache.reset()


def create_extension(value, critical):
    return x509.Extension(value.oid, critical, value)


def relative_datetime(td):
    return datetime.datetime.utcnow() + td


def test_empty_trust_store(ca_workspace):
    cert = ca_workspace.issue_new_self_signed()
    ca_workspace.assert_doesnt_validate(cert)


def test_simple_issuance(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_validates(cert, [cert, root])


def test_untrusted_issuer(ca_workspace):
    ca_workspace.issue_new_trusted_root()
    root = ca_workspace.issue_new_self_signed()
    cert = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_doesnt_validate(cert)


def test_intermediate(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca_certificate(root)
    cert = ca_workspace.issue_new_leaf(intermediate)

    ca_workspace.assert_validates(
        cert, [cert, intermediate, root], extra_certs=[intermediate]
    )


def test_ca_true_required(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    cert1 = ca_workspace.issue_new_leaf(root)
    cert2 = ca_workspace.issue_new_leaf(root, extra_extensions=[
        create_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    ])
    untrusted1 = ca_workspace.issue_new_leaf(cert1)
    untrusted2 = ca_workspace.issue_new_leaf(cert2)

    ca_workspace.assert_validates(cert1, [cert1, root])
    ca_workspace.assert_validates(cert2, [cert2, root])
    ca_workspace.assert_doesnt_validate(untrusted1, extra_certs=[cert1])
    ca_workspace.assert_doesnt_validate(untrusted2, extra_certs=[cert2])

    root = ca_workspace.issue_new_self_signed()
    ca_workspace.add_trusted_root(root)
    leaf = ca_workspace.issue_new_leaf(root)
    ca_workspace.assert_doesnt_validate(leaf, extra_certs=[root])


def test_pathlen(ca_workspace):
    root = ca_workspace.issue_new_trusted_root(path_length=0)
    intermediate = ca_workspace.issue_new_ca_certificate(root)
    direct = ca_workspace.issue_new_leaf(root)
    cert = ca_workspace.issue_new_leaf(intermediate)

    ca_workspace.assert_validates(direct, [direct, root])
    ca_workspace.assert_doesnt_validate(cert, extra_certs=[intermediate])

    root = ca_workspace.issue_new_trusted_root(path_length=1)
    direct1 = ca_workspace.issue_new_leaf(root)
    intermediate1 = ca_workspace.issue_new_ca_certificate(root)
    direct2 = ca_workspace.issue_new_leaf(intermediate1)
    intermediate2 = ca_workspace.issue_new_ca_certificate(intermediate)
    cert = ca_workspace.issue_new_leaf(intermediate2)

    ca_workspace.assert_validates(direct1, [direct1, root])
    ca_workspace.assert_validates(
        direct2, [direct2, intermediate1, root], extra_certs=[intermediate1]
    )
    ca_workspace.assert_doesnt_validate(
        cert, extra_certs=[intermediate1, intermediate2]
    )


def test_conflicting_pathlen(ca_workspace):
    root = ca_workspace.issue_new_trusted_root(path_length=1)
    intermediate1 = ca_workspace.issue_new_ca_certificate(root, path_length=2)
    intermediate2 = ca_workspace.issue_new_ca_certificate(intermediate1)
    leaf = ca_workspace.issue_new_leaf(intermediate2)

    ca_workspace.assert_doesnt_validate(
        leaf, extra_certs=[intermediate1, intermediate2]
    )


def test_leaf_validity(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    expired = ca_workspace.issue_new_leaf(
        root,
        not_valid_before=relative_datetime(-datetime.timedelta(days=2)),
        not_valid_after=relative_datetime(-datetime.timedelta(days=1)),
    )
    not_yet_valid = ca_workspace.issue_new_leaf(
        root,
        not_valid_before=relative_datetime(datetime.timedelta(days=1)),
        not_valid_after=relative_datetime(datetime.timedelta(days=2)),
    )

    ca_workspace.assert_doesnt_validate(expired)
    ca_workspace.assert_doesnt_validate(not_yet_valid)


def test_root_validity(ca_workspace):
    expired_root = ca_workspace.issue_new_trusted_root(
        not_valid_before=relative_datetime(-datetime.timedelta(days=2)),
        not_valid_after=relative_datetime(-datetime.timedelta(days=1)),
    )
    not_yet_valid_root = ca_workspace.issue_new_trusted_root(
        not_valid_before=relative_datetime(datetime.timedelta(days=1)),
        not_valid_after=relative_datetime(datetime.timedelta(days=2)),
    )

    expired_root_leaf = ca_workspace.issue_new_leaf(expired_root)
    not_yet_valid_root_leaf = ca_workspace.issue_new_leaf(not_yet_valid_root)

    ca_workspace.assert_doesnt_validate(expired_root_leaf)
    ca_workspace.assert_doesnt_validate(not_yet_valid_root_leaf)


def test_rsa_key_too_small(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    leaf = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_rsa_key(key_size=1024)
    )

    ca_workspace.assert_doesnt_validate(leaf)


def test_unsupported_signature_hash(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    md5_leaf = ca_workspace.issue_new_leaf(
        root, signature_hash_algorithm=hashes.MD5()
    )
    sha1_leaf = ca_workspace.issue_new_leaf(
        root, signature_hash_algorithm=hashes.SHA1()
    )

    ca_workspace.assert_doesnt_validate(md5_leaf)
    ca_workspace.assert_doesnt_validate(sha1_leaf)

    root = ca_workspace.issue_new_trusted_root(
        key=key_cache.generate_ec_key(ec.SECP256R1())
    )
    sha1_leaf = ca_workspace.issue_new_leaf(
        root, signature_hash_algorithm=hashes.SHA1()
    )

    ca_workspace.assert_doesnt_validate(sha1_leaf)


def test_maximum_chain_depth(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    intermediates = []
    ca = root
    for _ in range(16):
        ca = ca_workspace.issue_new_ca_certificate(ca)
        intermediates.append(ca)
    leaf = ca_workspace.issue_new_leaf(ca)

    ca_workspace.assert_doesnt_validate(leaf, extra_certs=intermediates)


def test_unsupported_critical_extension_leaf(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    leaf = ca_workspace.issue_new_leaf(root, extra_extensions=[
        create_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.0"), value=b""
            ),
            critical=True
        )
    ])

    ca_workspace.assert_doesnt_validate(leaf)


def test_unsupported_critical_extension_intermediate(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca_certificate(
        root,
        extra_extensions=[
            create_extension(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier("1.0"), value=b""
                ),
                critical=True
            )
        ]
    )
    leaf = ca_workspace.issue_new_leaf(intermediate)

    ca_workspace.assert_doesnt_validate(leaf, extra_certs=[intermediate])


def test_name_validation(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_validates(
        cert, [cert, root], name=x509.DNSName("example.com")
    )
    ca_workspace.assert_doesnt_validate(
        cert, name=x509.DNSName("google.com")
    )
    ca_workspace.assert_doesnt_validate(
        cert, name=x509.DNSName("sub.example.com")
    )
    ca_workspace.assert_doesnt_validate(
        cert, name=x509.IPAddress(ipaddress.IPv4Network("127.0.0.1"))
    )

    wildcard_cert = ca_workspace.issue_new_leaf(
        root, names=[x509.DNSName("*.example.com")]
    )
    ca_workspace.assert_validates(
        wildcard_cert, [wildcard_cert, root],
        name=x509.DNSName("sub.example.com")
    )
    ca_workspace.assert_doesnt_validate(
        wildcard_cert, name=x509.DNSName("example.com")
    )
    ca_workspace.assert_doesnt_validate(
        wildcard_cert, name=x509.DNSName("sub.sub.example.com")
    )
    ca_workspace.assert_doesnt_validate(
        wildcard_cert, name=x509.DNSName("google.com")
    )

    empty_san_cert = ca_workspace.issue_new_leaf(root, names=[])
    ca_workspace.assert_doesnt_validate(
        empty_san_cert, name=x509.DNSName("example.com")
    )

    no_san_cert = ca_workspace.issue_new_leaf(root, names=None)
    ca_workspace.assert_doesnt_validate(
        no_san_cert, name=x509.DNSName("example.com")
    )


@pytest.mark.parametrize(("trusted", "name"), [
    (False, "example.com"),
    (True, "sub.example.com"),
    (True, "sub.sub.example.com"),
    (False, "subsub.example.com"),
    (False, "sub.subsub.example.com"),
    (False, "google.com"),
    (False, "subsub.google.com"),
    (True, "sub.google.com"),
    (True, "sub.sub.google.com"),
    (True, "sub.sub.google.com"),
    (False, "mozilla.org"),
])
def test_name_constraints(ca_workspace, trusted, name):
    root = ca_workspace.issue_new_trusted_root(extra_extensions=[
        create_extension(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.DNSName(".example.com"),
                    x509.DNSName("sub.google.com"),
                    x509.IPAddress(ipaddress.IPv4Network("10.10.0.0/24")),
                ],
                excluded_subtrees=[
                    x509.DNSName("subsub.example.com"),
                ],
            ),
            critical=False,
        )
    ])

    cert = ca_workspace.issue_new_leaf(root, names=[x509.DNSName(name)])
    if trusted:
        ca_workspace.assert_validates(
            cert, [cert, root], name=x509.DNSName(name)
        )
    else:
        ca_workspace.assert_doesnt_validate(cert, name=x509.DNSName(name))


def test_name_constraints_excluded(ca_workspace):
    root = ca_workspace.issue_new_trusted_root(extra_extensions=[
        create_extension(
            x509.NameConstraints(
                permitted_subtrees=[],
                excluded_subtrees=[
                    x509.DNSName("example.com"),
                ],
            ),
            critical=False,
        )
    ])
    example_cert = ca_workspace.issue_new_leaf(
        root, names=[x509.DNSName("example.com")]
    )
    example_sub_cert = ca_workspace.issue_new_leaf(
        root, names=[x509.DNSName("sub.example.com")]
    )
    google_cert = ca_workspace.issue_new_leaf(
        root, names=[x509.DNSName("google.com")]
    )

    ca_workspace.assert_doesnt_validate(
        example_cert, name=x509.DNSName("example.com")
    )
    ca_workspace.assert_doesnt_validate(
        example_sub_cert, name=x509.DNSName("sub.example.com")
    )
    ca_workspace.assert_validates(
        google_cert, [google_cert, root], name=x509.DNSName("google.com")
    )


def test_p256_chain(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root(
        key=key_cache.generate_ec_key(ec.SECP256R1())
    )
    leaf = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_ec_key(ec.SECP256R1())
    )

    ca_workspace.assert_validates(leaf, [leaf, root])


def test_mixed_chain(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    leaf = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_ec_key(ec.SECP256R1())
    )

    ca_workspace.assert_validates(leaf, [leaf, root])

    root = ca_workspace.issue_new_trusted_root(
        key=key_cache.generate_ec_key(ec.SECP256R1())
    )
    leaf = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_validates(leaf, [leaf, root])


def test_untrusted_issuer_p256(ca_workspace, key_cache):
    ca_workspace.issue_new_trusted_root(
        key=key_cache.generate_ec_key(ec.SECP256R1())
    )
    root = ca_workspace.issue_new_self_signed(
        key=key_cache.generate_ec_key(ec.SECP256R1())
    )
    cert = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_ec_key(ec.SECP256R1())
    )

    ca_workspace.assert_doesnt_validate(cert)


def test_unsupported_curve(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_ec_key(ec.SECP192R1())
    )

    ca_workspace.assert_doesnt_validate(cert)


def test_p384(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_ec_key(ec.SECP384R1())
    )

    ca_workspace.assert_validates(cert, [cert, root])


def test_dsa_unsupported(ca_workspace, key_cache):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(
        root, key=key_cache.generate_dsa_key()
    )

    ca_workspace.assert_doesnt_validate(cert)


def test_extended_key_usage(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(
        root, extended_key_usages=[x509.ExtendedKeyUsageOID.CLIENT_AUTH],
    )

    ca_workspace.assert_doesnt_validate(
        cert, extended_key_usage=x509.ExtendedKeyUsageOID.SERVER_AUTH
    )

    root = ca_workspace.issue_new_trusted_root(
        extended_key_usages=[x509.ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    cert = ca_workspace.issue_new_leaf(root)
    ca_workspace.assert_doesnt_validate(
        cert, extended_key_usage=x509.ExtendedKeyUsageOID.SERVER_AUTH
    )

    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca_certificate(
        root, extended_key_usages=[x509.ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    cert = ca_workspace.issue_new_leaf(intermediate)

    ca_workspace.assert_doesnt_validate(
        cert,
        extra_certs=[intermediate],
        extended_key_usage=x509.ExtendedKeyUsageOID.SERVER_AUTH,
    )


def test_extended_key_usage_any(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    cert = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_validates(
        cert, [cert, root],
        extended_key_usage=[x509.ExtendedKeyUsageOID.SERVER_AUTH]
    )


def test_missing_extended_key_usage(ca_workspace):
    root = ca_workspace.issue_new_trusted_root(extended_key_usages=None)
    cert = ca_workspace.issue_new_leaf(root)

    ca_workspace.assert_validates(
        cert, [cert, root],
        extended_key_usage=[x509.ExtendedKeyUsageOID.SERVER_AUTH]
    )

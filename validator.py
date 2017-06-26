from __future__ import absolute_import, division, unicode_literals

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class ValidationError(Exception):
    pass


def _build_name_mapping(roots):
    mapping = {}
    for root in roots:
        mapping.setdefault(root.subject, []).append(root)
    return mapping


class ValidationContext(object):
    def __init__(self, extra_certs=[]):
        self.timestamp = datetime.datetime.utcnow()
        self.extra_certs = extra_certs
        self._extra_certs_by_name = _build_name_mapping(extra_certs)


class X509Validator(object):
    def __init__(self, roots):
        self._roots = roots
        self._roots_by_name = _build_name_mapping(roots)

    def validate(self, cert, ctx=None):
        if ctx is None:
            ctx = ValidationContext()
        if not self._is_valid_cert(cert, ctx):
            raise ValidationError
        for chain in self._build_chain_from(cert, ctx, depth=0):
            return chain
        raise ValidationError

    def _find_potential_issuers(self, cert, ctx):
        for issuer in ctx._extra_certs_by_name.get(cert.issuer, []):
            yield issuer
        for issuer in self._roots_by_name.get(cert.issuer, []):
            yield issuer

    def _is_valid_cert(self, cert, ctx):
        return (
            cert.not_valid_before <= ctx.timestamp <= cert.not_valid_after and
            cert.public_key().key_size >= 2048
        )

    def _is_valid_issuer(self, cert, issuer, depth, ctx):
        # TODO:
        # - name constraints
        # - key parameter validation
        # - public_key matches signature type
        # - maximum chain depth
        # - valid signature algorithms

        if not self._is_valid_cert(issuer, ctx):
            return False

        try:
            basic_constraints = issuer.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            return False
        if not basic_constraints.ca:
            return False
        if (
            basic_constraints.path_length is not None and
            basic_constraints.path_length < depth
        ):
            return False

        public_key = issuer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            try:
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except InvalidSignature:
                return False
        else:
            return False
        return True

    def _build_chain_from(self, cert, ctx, depth):
        if cert in self._roots:
            yield [cert]
            return
        for issuer in self._find_potential_issuers(cert, ctx):
            if self._is_valid_issuer(cert, issuer, depth, ctx):
                for chain in self._build_chain_from(issuer, ctx, depth=depth+1):
                    yield [cert] + chain

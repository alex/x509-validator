from __future__ import absolute_import, division, unicode_literals

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


# TODO: https://github.com/pyca/cryptography/issues/3745
ANY_EXTENDED_KEY_USAGE_OID = x509.ObjectIdentifier("2.5.29.37.0")


class ValidationError(Exception):
    pass


def _build_name_mapping(roots):
    mapping = {}
    for root in roots:
        mapping.setdefault(root.subject, []).append(root)
    return mapping


def _hostname_matches(hostname, cert_hostname):
    hostname_prefix, hostname_rest = hostname.split(u".", 1)
    cert_hostname_prefix, cert_hostname_rest = cert_hostname.split(u".", 1)
    return (
        (
            cert_hostname_prefix == u"*" or
            cert_hostname_prefix == hostname_prefix
        ) and
        cert_hostname_rest == hostname_rest
    )


def _name_constraint_matches(hostname, name_constraint):
    if not isinstance(name_constraint, x509.DNSName):
        return False
    constraint_hostname = name_constraint.value

    if constraint_hostname.startswith(u"."):
        return hostname.endswith(constraint_hostname)
    else:
        return (
            hostname == constraint_hostname or
            hostname.endswith(u"." + constraint_hostname)
        )


class ValidationContext(object):
    def __init__(self, name, extended_key_usage, extra_certs=[]):
        self.name = name
        self.extended_key_usage = extended_key_usage
        self.extra_certs = extra_certs
        self._extra_certs_by_name = _build_name_mapping(extra_certs)
        self.timestamp = datetime.datetime.utcnow()


_MAX_CHAIN_DEPTH = 8
_SUPPORTED_EXTENSIONS = {x509.ExtensionOID.BASIC_CONSTRAINTS}
_SUPPORTED_CURVES = {ec.SECP256R1, ec.SECP384R1}


class X509Validator(object):
    def __init__(self, roots):
        self._roots = roots
        self._roots_by_name = _build_name_mapping(roots)

    def validate(self, cert, ctx):
        if not self._is_valid_cert(cert, ctx):
            raise ValidationError

        if not self._is_name_correct(cert, ctx.name):
            raise ValidationError

        for chain in self._build_chain_from(cert, ctx, depth=0):
            return chain
        raise ValidationError

    def _find_potential_issuers(self, cert, ctx):
        for issuer in ctx._extra_certs_by_name.get(cert.issuer, []):
            yield issuer
        for issuer in self._roots_by_name.get(cert.issuer, []):
            yield issuer

    def _is_name_correct(self, cert, name):
        if not isinstance(name, x509.DNSName):
            raise ValidationError
        hostname = name.value
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except x509.ExtensionNotFound:
            return False

        for entry in san:
            if not isinstance(entry, x509.DNSName):
                # TODO: verify that it's not an error to see strange SAN
                # entries
                continue
            if _hostname_matches(hostname, entry.value):
                return True
        return False

    def _check_name_constraints(self, cert, name):
        try:
            nc = cert.extensions.get_extension_for_class(
                x509.NameConstraints
            ).value
        except x509.ExtensionNotFound:
            return True

        assert isinstance(name, x509.DNSName)
        if nc.permitted_subtrees:
            for constraint in nc.permitted_subtrees:
                if _name_constraint_matches(name.value, constraint):
                    break
            else:
                return False

        for constraint in nc.excluded_subtrees:
            if _name_constraint_matches(name.value, constraint):
                return False

        return True

    def _is_valid_cert(self, cert, ctx):
        try:
            eku = cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except x509.ExtensionNotFound:
            # No EKU extension means "anything is permitted"
            pass
        else:
            if (
                ctx.extended_key_usage not in eku and
                ANY_EXTENDED_KEY_USAGE_OID not in eku
            ):
                return False

        return (
            cert.not_valid_before <= ctx.timestamp <= cert.not_valid_after and
            self._is_valid_public_key(cert.public_key()) and
            all(
                ext.oid in _SUPPORTED_EXTENSIONS
                for ext in cert.extensions if ext.critical
            )
        )

    def _is_valid_public_key(self, key):
        return (
            (isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048) or
            (
                isinstance(key, ec.EllipticCurvePublicKey) and
                type(key.curve) in _SUPPORTED_CURVES
            )
        )

    def _is_valid_issuer(self, cert, issuer, depth, ctx):
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

        if not self._check_name_constraints(issuer, ctx.name):
            return False

        public_key = issuer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if cert.signature_algorithm_oid not in [
                x509.SignatureAlgorithmOID.RSA_WITH_SHA256
            ]:
                return False

            try:
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except InvalidSignature:
                return False
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if cert.signature_algorithm_oid not in [
                x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256
            ]:
                return False

            try:
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            except InvalidSignature:
                return False
        else:
            # Unreachable because of the `_is_valid_public_key` check.
            return False
        return True

    def _build_chain_from(self, cert, ctx, depth):
        if depth > _MAX_CHAIN_DEPTH:
            return
        if cert in self._roots:
            yield [cert]
            return
        for issuer in self._find_potential_issuers(cert, ctx):
            if self._is_valid_issuer(cert, issuer, depth, ctx):
                chains = self._build_chain_from(issuer, ctx, depth=depth+1)
                for chain in chains:
                    yield [cert] + chain

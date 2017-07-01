from __future__ import absolute_import, division, unicode_literals

import datetime

from cryptography import x509


def create_extension(value, critical):
    return x509.Extension(value.oid, critical, value)


def relative_datetime(td):
    return datetime.datetime.utcnow() + td

from cryptography import x509


def create_extension(value, critical):
    return x509.Extension(value.oid, critical, value)

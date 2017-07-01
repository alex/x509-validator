# ``x509-validator``

**WARNING:** This has never received any sort of security review, don't use it.

This library is a pure-Python implementation of X.509 certificate path building
and validation, built on top of ``pyca/cryptography``.

## Usage

```python
from cryptography import x509

from validator import X509Validator, ValidationContext

validator = X509Validator([list-of-x509-certificates])
validator.validate(
    leaf_certificate
    ValidationContext(
        name=x509.DNSName(hostname),
        extra_certs=[list-of-intermediate-x509-certificates],
        extended_key_usage=x509.ExtendedKeyUsageOIDs.SERVER_AUTH,
    )
)

import base64
from collections import defaultdict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest


class KeyCache(object):
    def __init__(self, cached_entries):
        self._inuse_keys = defaultdict(list)
        self._free_keys = defaultdict(list)

        for entry in cached_entries:
            params = tuple(entry["params"])
            for key in entry["keys"]:
                key = serialization.load_der_private_key(
                    base64.b64decode(key),
                    password=None,
                    backend=default_backend(),
                )
                self._free_keys[params].append(key)

    def dump(self):
        cache_entries = []
        for (params, keys) in self._free_keys.items():
            cache_entries.append({
                "params": params,
                "keys": [
                    base64.b64encode(key.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()
                    ))
                    for key in keys
                ],
            })
        return cache_entries

    def generate_rsa_key(self, public_exponent=65537, key_size=2048):
        params = (public_exponent, key_size)
        if self._free_keys[params]:
            key = self._free_keys[params].pop()
        else:
            key = rsa.generate_private_key(*params, backend=default_backend())
        self._inuse_keys[params].append(key)
        return key

    def reset(self):
        for params, keys in self._inuse_keys.items():
            self._free_keys[params].extend(keys)
        self._inuse_keys.clear()


@pytest.fixture(scope="session")
def key_cache(request):
    keys = request.config.cache.get("x509-validator/keys", [])
    key_cache = KeyCache(keys)
    try:
        yield key_cache
    finally:
        request.config.cache.set("x509-validator/keys", key_cache.dump())

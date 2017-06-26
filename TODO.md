# Success

- Name constraint in permitted
- P256
- P384
- Ed25519

# Failure

- No SAN for cert
- Name constraint in excluded
- Name constraint not present
- Signature not correct
- Unsupported curve

# Need to write full test case description for

- AIA chasing
- CRL
- SCT
- OCSP
- Bad key type
- Unknown extensions
- Bad signature type
- issuer/subject matching?
- key usages
- extended key usages
- issuer alt names?
- maximum validity period

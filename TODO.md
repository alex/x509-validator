# Success

- Name constraint in permitted
- P256
- P384
- Ed25519

# Failure

- Root missing ca:true
- Conflicting pathlens
- No SAN for cert
- Name constraint in excluded
- Name constraint not present
- Signature not correct
- RSA key too small
- maximum chain depth
- Unknown critical extension

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

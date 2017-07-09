# Test cases that need to be written (which imply additional code)

## Success

- Ed25519
    - Leaf
    - CA

## Failure

- Ed25519
    - bad signature
    - invalid signature oid
- Signature not correct (currently implicitly tested)
- SPKI contains random oid
    - Leaf
    - intermediate

## Need to write full test case description for

- RSA-PSS signatures
- CRL
- SCT
- OCSP
- ski/aki?
- issuer/subject matching?
- key usages
- issuer alt names?
- maximum validity period
- policy constraints/certificate policies?
- ?

from __future__ import absolute_import, division, unicode_literals

from cryptography import x509

from .utils import create_ca_issuer


def test_follows_aia(ca_workspace, server):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)
    intermediate_url = server.create_aia_url(intermediate)

    cert = ca_workspace.issue_new_leaf(
        intermediate, ca_issuers=[intermediate_url]
    )

    ca_workspace.assert_validates(cert, [cert, intermediate, root])


def test_non_http_aia(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)
    cert = ca_workspace.issue_new_leaf(
        intermediate, ca_issuers=[create_ca_issuer("ldap://nonsense")]
    )

    ca_workspace.assert_doesnt_validate(cert)



def test_multiple_aia(ca_workspace, server):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)
    intermediate_url = server.create_aia_url(intermediate)
    cert = ca_workspace.issue_new_leaf(
        intermediate, ca_issuers=[
            x509.AccessDescription(
                x509.AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier("http://example.com")
            ),
            intermediate_url
        ]
    )

    ca_workspace.assert_validates(cert, [cert, intermediate, root])


def test_aia_invalid_cert(ca_workspace, server):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)

    aia_url = server.create_aia_url(b"gibberish - definitely not a cert")
    cert = ca_workspace.issue_new_leaf(intermediate, ca_issuers=[aia_url])

    ca_workspace.assert_doesnt_validate(cert)
    ca_workspace.assert_validates(
        cert, [cert, intermediate, root], extra_certs=[intermediate]
    )


def test_aia_404(ca_workspace, server):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)

    aia_url = create_ca_issuer("{}/not-a-real-url".format(server.base_url))
    cert = ca_workspace.issue_new_leaf(intermediate, ca_issuers=[aia_url])

    ca_workspace.assert_doesnt_validate(cert)
    ca_workspace.assert_validates(
        cert, [cert, intermediate, root], extra_certs=[intermediate]
    )


def test_aia_bad_address(ca_workspace):
    root = ca_workspace.issue_new_trusted_root()
    intermediate = ca_workspace.issue_new_ca(root)

    aia_url = create_ca_issuer("http://host.invalid/")
    cert = ca_workspace.issue_new_leaf(intermediate, ca_issuers=[aia_url])

    ca_workspace.assert_doesnt_validate(cert)
    ca_workspace.assert_validates(
        cert, [cert, intermediate, root], extra_certs=[intermediate]
    )


def test_aia_to_untrusted(ca_workspace, server):
    root = ca_workspace.issue_new_trusted_root()
    intermediate1 = ca_workspace.issue_new_ca(root)
    intermediate2 = ca_workspace.issue_new_ca(root)

    aia_url = server.create_aia_url(intermediate2)
    # Create a child of intermediate1, with an AIA to intermediate2
    cert = ca_workspace.issue_new_leaf(intermediate1, ca_issuers=[aia_url])

    ca_workspace.assert_doesnt_validate(cert)
    ca_workspace.assert_validates(
        cert, [cert, intermediate1, root], extra_certs=[intermediate1]
    )

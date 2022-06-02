
authCMSMFA = 'http://schemas.microsoft.com/claims/multipleauthn'
authCPSSL = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
authCPAS = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'

bindPost = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

consUndefined = 'urn:oasis:names:tc:SAML:2.0:consent:undefined'
consImplicit = 'urn:oasis:names:tc:SAML:2.0:consent:current-implicit'


SamlNS = {
    'urn:oasis:names:tc:SAML:2.0:protocol': 'samlp', 
    'http://www.w3.org/2000/09/xmldsig#': 'ds', 
    'urn:oasis:names:tc:SAML:2.0:assertion': 'saml',
    'urn:oasis:names:tc:SAML:2.0:metadata': 'md',
    'http://www.w3.org/2001/XMLSchema-instance' : 'xsi',
    'http://www.w3.org/2001/XMLSchema': 'xs',
}


SamlNameIdUnspecified = 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified'
SamlNameIdEmailAddress = 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
SamlNameIdTransient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
SamlNameIdPersistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'

SamlStatusSuccess = 'urn:oasis:names:tc:SAML:2.0:status:Success'

SamlStatusAuthnFailed = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
SamlStatusInvalidNameIDPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy'
SamlStatusNoAuthnContext = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext'
SamlStatusNoPassive = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive'
SamlStatusRequestDenied = 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied'
SamlStatusRequestor = 'urn:oasis:names:tc:SAML:2.0:status:Requestor'
SamlStatusRequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported'
SamlStatusResponder = 'urn:oasis:names:tc:SAML:2.0:status:Responder'
SamlStatusUnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal'
SamlStatusUnsupportedBinding = 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding'
SamlStatusVersionMismatch = 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch'

SamlC14nAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#'

# lxml etree tags
dsSignatureTag = '{http://www.w3.org/2000/09/xmldsig#}Signature'
dsSignedInfoTag = '{http://www.w3.org/2000/09/xmldsig#}SignedInfo'
dsDigestValueTag = '{http://www.w3.org/2000/09/xmldsig#}DigestValue'
dsSignatureValueTag = '{http://www.w3.org/2000/09/xmldsig#}SignatureValue'
dsX509CertificateTag = '{http://www.w3.org/2000/09/xmldsig#}X509Certificate'

samlAssertionTag = '{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'
samlIssuerTag = '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'

dsSigAlgValue = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'

HTTP_Redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

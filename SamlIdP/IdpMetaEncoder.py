from copy import deepcopy

import xmltodict
from .SamlSerializer import serialize_cert

def encodeIdPMetaData(idp, ssologin):

    idpmeta = deepcopy(_template_IdPMetaData)
    idpmeta['md:EntityDescriptor']['@entityID'] = idp.idp_id
    kdesc = idpmeta['md:EntityDescriptor']['md:IDPSSODescriptor']['md:KeyDescriptor']
    kdesc[0]['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate'] = serialize_cert(idp.cert)
    idpmeta['md:EntityDescriptor']['md:IDPSSODescriptor']['md:SingleSignOnService']['@Location'] = ssologin

    return xmltodict.unparse(idpmeta)


_template_IdPMetaData = {
    'md:EntityDescriptor': {
        '@xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        '@entityID': '_IdP Entity ID **',
        'md:IDPSSODescriptor': {
            '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
            'md:KeyDescriptor': [
                {
                    '@use': 'signing',
                    'ds:KeyInfo': {
                        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                        'ds:X509Data': {
                            'ds:X509Certificate': '_IdP Certificate **'
                        }
                    }
                }
            ],
            'md:NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'md:SingleSignOnService': {
                '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                '@Location': '_IdP Logon URL **'
            }
        },
    }
}

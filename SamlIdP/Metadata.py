import logging as logger

import xmltodict

from .constants import SamlNS

HTTP_Redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'


def _getMetaURL(url):
    """ Retrieve metadata from a URL """

    from requests import get

    logger.info(f'Retrieving metadata from {url}')

    res = get(url)
    
    if res.ok:
        return res.content
    
    else:
        raise Exception(f'Error on metadata URL: {res.reason}')


def _getMetaFile(metadata_path):
    """ Retrieve metadata from a file """
    
    with open(metadata_path,'rb') as f:
        return f.read()



def loadIdPMetadata(idp_config):
    """" Load IdP Metadata from file or URL, meld with idp_config """

    idp_meta = {}

    if idp_config.get('idp_metadata'):
        xml_data = _getMetaFile(idp_config['idp_metadata'])

    elif idp_config.get('idp_meta_url'):
        xml_data = _getMetaURL(idp_config['idp_meta_url'])

    else:
        return idp_config

    root = xmltodict.parse(
        xml_data,
        process_namespaces=True,
        namespaces=SamlNS
    )

    entity = root['md:EntityDescriptor']
    idp_id = entity['@entityID']

    ssolist=[]
    slolist=[]
    cert = None

    assert 'md:IDPSSODescriptor' in entity, 'Not IDP metadata'

    idpsso = entity['md:IDPSSODescriptor']

    if 'md:KeyDescriptor' in idpsso:
        keydescr = idpsso['md:KeyDescriptor']

        if isinstance(keydescr, dict):
            keydescr = [keydescr]
        
        for key in keydescr:
            if key['@use'] == 'signing':
                cert = key['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate']
                if cert:
                    cert = '-----BEGIN CERTIFICATE-----'+cert+'-----END CERTIFICATE-----'
                    cert = cert.encode('utf-8') 
                break
        
    if 'md:NameIDFormat' in idpsso:
        nameid_fmt = idpsso['md:NameIDFormat']
    else:
        nameid_fmt = None

    if 'md:SingleSignOnService' in idpsso:
        ssos = idpsso['md:SingleSignOnService']

        if isinstance(ssos,dict):
            ssos = [ssos]

        for sso in ssos:
            if sso['@Binding'] == HTTP_Redirect:
                ssolist.append(sso['@Location'])

    if 'md:SingleLogOutService' in idpsso:
        slos = idpsso['md:SingleLogOutService']

        if isinstance(slos,dict):
            ssos = [slos]

        for slo in slos:
            if slo['@Binding'] == HTTP_Redirect:
                slolist.append(slo['@Location'])
    
    idp_meta['idp_id'] = idp_id
    
    idp_meta['default_nameid'] = nameid_fmt
    idp_meta['idp_cert'] = cert
    idp_meta['idp_url'] = ssolist[0] if ssolist else None

    idp_meta.update(idp_config)

    return idp_meta



def loadSPMetadata(sp_config):
    """ Load SP Metadata from file or URL, meld wtih sp_config """

    sp_meta = {}

    if sp_config.get('sp_metadata'):
        xml_data = _getMetaFile(sp_config['sp_metadata'])

    elif sp_config.get('sp_meta_url'):
        xml_data = _getMetaURL(sp_config['sp_meta_url'])

    else:
        return sp_config

    ssolist = []
    slolist = []
    cert = None

    root = xmltodict.parse(
        xml_data,
        process_namespaces=True,
        namespaces=SamlNS
    )

    entity = root['md:EntityDescriptor']
    sp_id = entity['@entityID']

    assert 'md:SPSSODescriptor' in entity, 'Not SP metadata'

    spsso = entity['md:SPSSODescriptor']

    authn_signed = spsso['@AuthnRequestsSigned']

    if 'md:NameIDFormat' in spsso:
        nameid_fmt = spsso['md:NameIDFormat']
    else:
        nameid_fmt = None

    if 'md:KeyDescriptor' in spsso:
        keydescr = spsso['md:KeyDescriptor']

        if isinstance(keydescr, dict):
            keydescr = [keydescr]
        
        for key in keydescr:
            if key['@use'] == 'signing':
                cert = key['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate']
                break
    
    if 'md:SingleLogoutService' in spsso:
        
        slos = spsso['md:SingleLogoutService']

        if isinstance(slos,dict):
            slos = [slos]

        for slo in slos:
            if slo['@Binding'] == HTTP_Redirect:
                slolist.append(slo['@Location'])


    if 'md:AssertionConsumerService' in spsso:

        ssos = spsso['md:AssertionConsumerService']
        if isinstance(ssos,dict):
            ssos = [ssos]

        for sso in ssos:
            if sso['@Binding'] == HTTP_POST:
                ssolist.append(sso['@Location'])        


    sp_meta['SPEntityId'] = sp_id
    sp_meta['ACSList'] = ssolist
    sp_meta['sp_cert'] = cert
    sp_meta['NameIdFmt'] = nameid_fmt
    sp_meta['AuthnRequestsSigned'] = authn_signed

    sp_meta.update(sp_config)

    return sp_meta


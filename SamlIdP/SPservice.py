from .constants import *
from .SamlSerializer import SamlRequestSerializer
import logging

allServiceProviders = {}

class SamlSPs:
    """ SAML Service Provider definition """

    def __init__(self, idP, sp_config):

        self.idP = idP
        self.idp_id = idP.idp_id

        self.sp_id = sp_config['SPEntityId']
        self.acs = sp_config.get('ACSList',[])

        assert self.sp_id, 'Config error: SP Entity ID not specified'
        assert self.acs, 'Config error: SP Assertion Consumer URL not specified'
        assert self.sp_id not in allServiceProviders, 'Config error: SP instance already defined'

        self.defRelayState = sp_config.get('RelayState','')
        self.defConsent = sp_config.get('DefaultConsent',consUndefined)
        self.defNameIdFmt = sp_config.get('DefaultNameIDPol', SamlNameIdTransient)
        self.protocolBinding = sp_config.get('ProtocolBinding',bindPost)

        self.authn_attrs = sp_config.get('AuthAttrs',['uid'])
        self.authn_nameIdAttr = sp_config.get('NameIdAttr')

        self.sp_cert = sp_config.get('sp_cert')

        # Use this to deserialize and maybe verify signed query string
        self.deserializer = SamlRequestSerializer(cert=self.sp_cert)
    
        allServiceProviders[self.sp_id] = self

        logging.info(f'IdP: {idP.idp_id} added Service Provider: {self.sp_id}')


    @classmethod
    def getSamlSP(this,sp_id):
        """ Find SamlSPs for an entity id"""

        return allServiceProviders.get(sp_id)


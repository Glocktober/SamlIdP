from .SPservice import SamlSPs
from .ResponseHandler import ResponseHandler
from .SamlSerializer import SamlResponseSigner

class IdPservice:
    """ SAML Identity Provider definition """

    def __init__(self, auth, idp_config):

        self.auth = auth

        # Create the response handler
        self.responseHandler = ResponseHandler(auth)

        self.idp_id = idp_config['entityId']
        self.cert = idp_config['x509Cert']
        self.key = idp_config['priv_key']
        self.passwd = idp_config.get('priv_password')
        self.destination = idp_config.get('destination')

        
        assert self.idp_id, 'Config error: missing IdP Entity Id'
        assert self.cert, 'Config error: IdP x509 certificate missing'
        assert self.key, 'Config error: IdP siging key missing'
        
        self.signer = SamlResponseSigner(self.cert, self.key, self.passwd)
        
        self.permit_forceAuthn = idp_config.get('permit_forceAuthn',True)

        # Register defined service providers
        for sp in idp_config['splist']:
            SamlSPs(idP=self, sp_config=sp)


    @property
    def is_authenticated(self):
        return self.auth.is_authenticated
    
    def signResponse(self,saml_response):
        return self.signer.signSamlResponse(saml_response)

    def verifyResponse(self,saml_response):
        return self.signer.verifySamlResponse(saml_response)

    def unauthenticate(self):
        return self.auth.unauthenticate()

    def initiate_login(self, *args, **kwargs):
        return self.auth.initiate_login(*args, **kwargs)

    def handleResponse(self, saml_request):
        return self.responseHandler.handleResponse(saml_request)

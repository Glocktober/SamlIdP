import os

from flask import (
    Blueprint, 
    Response, 
    abort, 
    current_app, 
    request, 
    session,
    url_for
)
from .IdPservice import IdPservice
from .RequestDecoder import RequestDecoder
from .IdpMetaEncoder import encodeIdPMetaData

DIR=os.path.dirname(__file__)
abspath = lambda p : os.path.join(DIR,p)

class   SamlIdP(Blueprint):
    """ SAML Identity Provider Flask Blueprint """

    def __init__(self, *, auth, idp_config, app=None):

        # create the IdP (and underling SP's)
        self.idP = IdPservice(auth=auth, idp_config=idp_config)

        # make this a Blueprint
        url_prefix = idp_config.get('url_prefix','')
        Blueprint.__init__(self, 
            name='samlidp', 
            import_name=__name__,
            template_folder=abspath('templates')
            )

        # Set up endpoint to handle SAML requests
        self.add_url_rule(
            '/saml2',
            'saml2',
            self.saml2req,
            methods=['GET']
        )

        self.add_url_rule(
            '/saml2/metadata',
            'saml2meta',
            self.saml2Meta,
            methods=['GET']   
        )

        self.add_url_rule(
            '/saml2/.logout',
            'logout',
            self.logout,
        )

        if app:
            # self register blueprint if app is specified
            app.register_blueprint(self, url_prefix=url_prefix)


    def saml2req(self):
        """ /saml2 API endpoint for SAMLRequest """

        request_url = request.url.decode()
    
        try:
            saml_request = RequestDecoder(request_url)
        
        except Exception as e:
            current_app.logger.info(f'Failed to decode SAMLrequest {str(e)}', exc_info=True)
            abort(Response(status=400, response=f'Failure decoding SAMLRequest'))
        
        try:
            # Returns either direct response, or redirect to authenticate
            return saml_request.service()

        except Exception as e:
            current_app.logger.error(f'Error handling SAMLRequest: {str(e)}',exc_info=True)
            abort(Response(status=500, response=f'Error handling SAMLRequest: service failed to process request'))
    

    def saml2Meta(self):
        """ SAML IdP Metadata """
        
        metaxml = encodeIdPMetaData(self.idP, ssologin=url_for('.saml2',_external=True))
        return Response(response=metaxml, headers={
            'Content-Type':'application/xml',
        })


    def logout(self):
        session.clear()
        return 'OK'
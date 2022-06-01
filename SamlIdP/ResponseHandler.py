from secrets import token_hex

from flask import (
    Response,
    abort, 
    current_app,
    render_template,
    session, 
)

from .constants import *
from .ResponseEncoder import (
    ResponseEncoder, 
    ErrorResponseEncoder,
)
from .RequestDecoder import RequestThawed



class   ResponseHandler:
    """ Create SAMLResponse from SAMLRequest and verify authentication """

    post_redir_template = 'redir_post.html'

    def __init__(self, authn):

        self.authn = authn

        authn.after_auth_hooks['SA'] = self.after_authn


    @classmethod
    def handleResponse(this, saml_request):
        """ Complete authentication response """

        status = saml_request.responseStatus

        current_app.logger.info(f'Authn Request {saml_request.requestId} for SP "{saml_request.issuer}"')
        
        if status == SamlStatusSuccess and saml_request.idP.is_authenticated and not saml_request.forceAuthn:
            # immediate success return
            current_app.logger.info(f'Request {saml_request.requestId} satisfied by previous authentication')
            return this.send_success_response(saml_request)

        elif status != SamlStatusSuccess:
            # immediate error return
            return this.send_error_response(saml_request)

        else:
            # freeze saml_request for primary authentication verification
            reauth = saml_request.forceAuthn

            if reauth:
                saml_request.idP.unauthenticate()
            
                # So we don't get here twice:
                saml_request.forceAuthn = False

            iced_request = saml_request.freeze()

            key = 'SA' + token_hex(5)
            session[key] = iced_request
            
            nkwargs={
                'force_reauth': reauth,
                'reqid' : 'Pri' + saml_request.requestId,
                'after': 'SA',
                'SA': key,
            }
            
            current_app.logger.info(f'Froze request {saml_request.requestId} for primary authentication')

            return saml_request.idP.initiate_login(**nkwargs)
    

    @classmethod
    def send_error_response(this, saml_request):
        """ Create and send a SAMLResponse for an Error. """

        eresp = ErrorResponseEncoder(saml_request)

        short_stat = saml_request.responseStatus.split(':')[-1]

        current_app.logger.info(f'Creating Error response {eresp.responseId} in reply to {saml_request.requestId}')
        current_app.logger.info(f'Request {saml_request.requestId} with error: [{short_stat}], {saml_request.responseStatusMessage}')
        
        return this.saml_post_redirect(
            url=saml_request.acs, payload={
            'SAMLResponse': eresp.serialize().decode(),
            'RelayState': saml_request.relayState
        })

    
    @classmethod
    def send_success_response(this, saml_request):
        """ Create a SAMLResponse for a succesful return. """

        resp = ResponseEncoder(saml_request)

        acs_url = saml_request.acs

        current_app.logger.info(f'Creating Success response {resp.responseId} in reply to {saml_request.requestId}')
        
        desired_attrs = saml_request.sp.authn_attrs
        session_attrs = session.get('attributes',{})

        resp_attrs = {}
        for attr in desired_attrs:
            if attr in session_attrs:
                resp_attrs[attr] = session_attrs[attr]

        nameId = saml_request.sp.authn_nameIdAttr
        
        resp.auth_info(attrs=resp_attrs, nameid=nameId)

        # sign, serialize, and b64encode:
        bresp = resp.serialize().decode()

        return this.saml_post_redirect( 
            url=acs_url,
            payload = {
                'SAMLResponse':bresp,
                'RelayState': saml_request.relayState
            }
        )


    @classmethod
    def saml_post_redirect(this, url, payload):
        """ Return POST-REDIRECT """

        return Response(
            response=render_template(this.post_redir_template, url=url, payload=payload),
            headers = {
                'Cache-Control': 'no-store, no-cache',
                'Pragma': 'no-cache',
                'Expires': -1
            })


    @classmethod
    def after_authn(this, relayState):
        """ Unthaw response and validate authentication """
        
        key = relayState['SA'][0]
        
        try:
            iced_request = session[key]
            del session[key]

        except Exception as e:
            current_app.logger.info(f'Failed to restore frozen session {key}')
            session.clear()
            abort(500, 'Something went wrong, please try again')

        saml_request = RequestThawed(iced_request)
        
        current_app.logger.info(f'Thawed request {saml_request.requestId} after primary authentication')
        
        if not saml_request.idP.is_authenticated:
            # sanity check
            saml_request.responseStatus = SamlStatusAuthnFailed
            saml_request.responseStatusMessage = 'Primary authentication failed'
        
        return saml_request.service()

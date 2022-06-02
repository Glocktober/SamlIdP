from datetime import datetime, timedelta
import json

from flask import current_app
import xmltodict

from .constants import *
from .SamlSerializer import SamlRequestSerializer
from .SPservice import SamlSPservice

resolve_leaf = lambda element: element['#text'] if element and '#text' in element else element


def saml_time(timestring):
    """ Return python datetime from ISO formatted date string """

    fmt1 = '%Y-%m-%dT%H:%M:%S.%fZ'
    fmt2 = '%Y-%m-%dT%H:%M:%SZ'
    # Choose the one that works - preferring fractional time version
    try:
        return datetime.strptime(timestring, fmt1)
    except:
        return datetime.strptime(timestring, fmt2)



class RequestDecoder:
    """ Decode SAMLRequest, service the request """

    def __init__(self, request_base, request_qs):

        self.request_base = request_base
        self.request_qs = request_qs.decode()
        
        # deserialze query string without signing verification
        self.saml_req_xml, self.relayState = SamlRequestSerializer.deserializeSamlRequest(request_qs=self.request_qs)
        
        self.root = xmltodict.parse(
            self.saml_req_xml,
            process_namespaces=True, 
            namespaces=SamlNS
        )

        self.request = self.root['samlp:AuthnRequest']
        
        # Can't set these until we'ver verified any query string signature
        self.sp = None
        self.idP = None

        # Mark these as failed to start with
        self.responseStatus = SamlStatusAuthnFailed
        self.responseMessage = 'Request is unverified'


    def freeze(self):
        """ Return state as JSON string """

        return json.dumps({
            'responseStatus': self.responseStatus,
            'responseStatusMessage': self.responseStatusMessage,
            'relayState': self.relayState,
            'root': self.root,
            'request_qs': self.request_qs,
            'request_base': self.request_base,
        })


    @property
    def version(self):
        return self.request['@Version']
    
    @property
    def requestId(self):
        return self.request['@ID']

    @property
    def issuedInstant(self):
        return saml_time(self.request['@IssueInstant'])

    @property
    def destination(self):
        return self.request.get('@Destination')
     
    @property
    def acs(self):
        return self.request.get('@AssertionConsumerServiceURL')

    @property
    def forceAuthn(self):
        forceAuthn = self.request.get('@ForceAuthn','false') == 'true'
        return forceAuthn and self.idP.permit_forceAuthn
    
    @forceAuthn.setter
    def forceAuthn(self, v):
        self.request['@ForceAuthn'] = 'true' if v else 'false'

    @property
    def issuer(self):
        issuer = self.request.get('saml:Issuer')
        return resolve_leaf(issuer)

    @property    
    def spid(self):
        # alias to request issuer URN
        return self.issuer

    @property
    def isPassive(self):
        return self.request.get('@IsPassive','false') == 'true'
    
    @property
    def nameIdFormat(self):
        fmt = None
        nameid_pol = self.request.get('samlp:NameIDPolicy')
        if nameid_pol:
            fmt = nameid_pol.get('@Format')
        return fmt if fmt else SamlNameIdTransient
    
    @property
    def nameIdCreate(self):
        crea = None
        nameid_pol = self.request.get('samlp:NameIDPolicy')
        if nameid_pol:
            crea = nameid_pol.get('@AllowCreate')
        return True if crea is None else crea == 'true'

    @property
    def protocolBinding(self):
        return self.request.get('@ProtocolBinding', bindPost)
    
    @property
    def consent(self):
        return self.request.get('@Consent')
    
    @consent.setter
    def consent(self, consent):
        self.request['@Consent'] = consent


    def findRequestErrors(self):
        """ Return error code or None if no errors """

        if self.version != '2.0':
            return SamlStatusVersionMismatch, f'Version 2.0 is required'

        self.sp = SamlSPservice.getSamlSP(self.issuer)

        if self.sp is None:
            raise Exception(f'Unknown Service Provider {self.issuer}')

        self.idP = self.sp.idP

        # validate any request signature
        try:
            self.sp.deserializer.verifySamlRequest(request_qs=self.request_qs)

        except Exception as e:
            current_app.logger.info(f'Request Verification Failed: {str(e)}')
            return SamlStatusRequestor, 'Signature verfication failed'
        
        if self.destination and self.destination != self.request_base:
            return SamlStatusRequestDenied, 'Incorrect Destination'

        if self.issuedInstant > datetime.utcnow() + timedelta(minutes=5):
            return SamlStatusAuthnFailed, 'Request is in the future'

        elif self.issuedInstant < datetime.utcnow() - timedelta(minutes=5):
            return SamlStatusAuthnFailed, 'Request has expired'
        
        if self.isPassive and not self.idP.is_authenticated:
            return SamlStatusNoPassive, 'Passive authentication failed'

        if self.acs is None:
            self.acs = self.sp.acs[0]

        if self.acs not in self.acs:
            return SamlStatusRequestor, 'Invalid Assertion Consumer Service'
        
        if self.nameIdFormat is None:
            self.nameIdFormat = self.sp.defNameIdFmt
        
        # if self.consent is None:
        #     self.consent = self.sp.defConsent
        
        if self.protocolBinding is None:
            self.protocolBinding = self.sp.protocolBinding

        elif self.protocolBinding != self.sp.protocolBinding:
            return SamlStatusUnsupportedBinding, f'{self.protocolBinding} is unsupported'
        
        return SamlStatusSuccess, 'Successful Authentication'


    def service(self):
        """ Service this request """

        status, reason = self.findRequestErrors()
        self.responseStatus = status
        self.responseStatusMessage = reason
        
        return self.idP.handleResponse(self)



class RequestThawed(RequestDecoder):
    """ Thaw frozen SAMLRequest (on return from authentication) """

    def __init__(self, frozen):

        all = json.loads(frozen)

        self.root = all['root']
        self.request = self.root['samlp:AuthnRequest']
        
        self.relayState = all['relayState']
        self.responseStatus = all['responseStatus']
        self.responseStatusMessage = all['responseStatusMessage']

        self.request_qs = all['request_qs']
        self.request_base = all['request_base']
        
        self.sp = SamlSPservice.getSamlSP(self.issuer)
        self.idP = self.sp.idP

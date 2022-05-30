from base64 import b64encode
from secrets import token_hex

import xmltodict

from .ResponseTemplate import samlResponseTemplate, samlErrorResponseTemplate
from .SPservice import SamlSPs

from .constants import *


newid = lambda: '_' + token_hex(16)


class ResponseEncoder:
    """ Encode a SAMLResponse """

    def __init__(self, saml_request):

        self.sp_id = saml_request.issuer
        self.sp = SamlSPs.getSamlSP(self.sp_id)
        self.idP = self.sp.idP

        # deep copy with fresh timestamps and id's
        self.root = samlResponseTemplate()
        self.resp = resp = self.root['samlp:Response']

        self.responseId = resp['@ID']

        # IdP id (destination of request) 
        idp_id = self.sp.idp_id
        resp['Issuer']['#text'] = idp_id
        resp['Assertion']['Issuer'] = idp_id
 
        # from SAMLRequest info 
        resp['Assertion']['Subject']['NameID']['@Format'] = saml_request.nameIdFormat
        resp['@Destination'] = saml_request.acs
        resp['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['@Recipient'] = saml_request.acs
        
        # The requesters request id
        resp['@InResponseTo'] = saml_request.requestId
        resp['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['@InResponseTo'] = saml_request.requestId
       
        # The SP URN id (i.e. issuer of the SAMLrequest)
        resp['Assertion']['Conditions']['AudienceRestriction']['Audience'] = saml_request.issuer 


    @property
    def status_code(self):
        return self.resp['samlp:Status']['samlp:StatusCode']['@Value']
    

    @status_code.setter
    def status_code(self, statuscode):
        self.resp['samlp:Status']['samlp:StatusCode']['@Value'] = statuscode


    @property
    def status_message(self):
        # StatusMessage is an optional element
        status_element = self.resp['samlp:Status']
        message_element = status_element.get('samlp:StatusMessage', None)
        if message_element:
            return self.resp['samlp:Status']['samlp:StatusMessage'].get('#text','')
        return ''


    @status_message.setter
    def status_message(self, message=''):
        self.resp['samlp:Status']['samlp:StatusMessage'] = {'#text':message}
        

    def auth_info(self,attrs, nameid=None):
        """ Add attribute assertions to the response """

        # adding authentication information presumes staus is Success
        self.resp['samlp:Status']['samlp:StatusCode']['@Value'] = SamlStatusSuccess

        # A reasonable NameID response (ignoring 'create' when needed)  
        format = self.resp['Assertion']['Subject']['NameID']['@Format']
        
        if nameid is None or format == SamlNameIdTransient:
            nameid = newid()
        
        self.resp['Assertion']['Subject']['NameID']['#text'] = nameid
        
        # create <Attribute> entries that will be added to <AttributeStatement>
        attr_list = []

        for attr in attrs:
            
            attr_list.append ({
                '@Name': attr,
                'AttributeValue' : attrs[attr],
            })

        # add (replace) the attributes to the response tree
        self.resp['Assertion']['AttributeStatement']['Attribute'] = attr_list

        
    def sign(self):
        """ Sign using response signing """

        # convert dict to raw saml bytes
        saml_data = xmltodict.unparse(self.root, full_document=False).encode('utf-8')
        
        return self.idP.signResponse(saml_data)


    def pretty(self):
        """ Return pretty printed response for show and tell """

        saml_data = self.sign()
        # round trip, returning pretty
        return xmltodict.unparse(xmltodict.parse(saml_data), full_document=False, pretty=True)


    def serialize(self):
        """ b64 encode the signed response for real work """
        
        return b64encode(self.sign())



class ErrorResponseEncoder:
    """ Encode a SAML Error Reply """

    def __init__(self, saml_request):

        # start with a deep copy of a template
        self.root = samlErrorResponseTemplate()
        self.resp = resp = self.root['samlp:Response']
        
        self.responseId = resp['@ID']
        
        # set required fields from saml_request
        resp['Issuer']['#text'] = saml_request.destination
        resp['@InResponseTo'] = saml_request.requestId

        self.status_code = saml_request.responseStatus
        self.status_message = saml_request.responseStatusMessage


    @property
    def status_code(self):
        return self.resp['samlp:Status']['samlp:StatusCode']['@Value']
    

    @status_code.setter
    def status_code(self, statuscode):
        self.resp['samlp:Status']['samlp:StatusCode']['@Value'] = statuscode


    @property
    def status_message(self):
        # StatusMessage is an optional element
        status_element = self.resp['samlp:Status']
        message_element = status_element.get('samlp:StatusMessage', None)
        if message_element:
            return self.resp['samlp:Status']['samlp:StatusMessage'].get('#text','')
        return ''


    @status_message.setter
    def status_message(self, message=''):
        self.resp['samlp:Status']['samlp:StatusMessage'] = {'#text':message}
        

    def serialize(self):
        """ Serialize and encode XML response """

        saml_data = xmltodict.unparse(self.root, full_document=False).encode('utf-8')
        return b64encode(saml_data)


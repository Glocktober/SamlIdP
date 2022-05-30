from copy import deepcopy
from datetime import datetime, timedelta
from secrets import token_hex

# Generate a random id
newid = lambda: '_' + token_hex(16)   # Azure and SimpleSaml require a leading character

# Time stamps in UTC time, ISO format
TIMEFORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
issue_instant_now = lambda: datetime.utcnow().strftime(TIMEFORMAT)
expire_time = lambda minutes: (datetime.utcnow() + timedelta(minutes=minutes)).strftime(TIMEFORMAT)


def samlResponseTemplate(expire_minutes=60):
    """ 
    response_dict = SamlResponseTemplate(expire_minutes)

    Return a new instance of the SamlResponse template with date/time fields
    set and identifiers created.

    Expiration time - i.e. 'NotOnOrAfter' values default to 60 minutes
    
    """

    # create a deep copy of the response template
    root = deepcopy(__saml_response_template)
     
    response = root['samlp:Response']
    assertion = response['Assertion']
    # add timestamps and identifiers to the template

    # issue instance/notbefore/authinstant time - we use the same
    instant = issue_instant_now()
    response['@ID'] = newid()
    response['@IssueInstant'] = instant
    assertion['@IssueInstant'] = instant
    assertion['Conditions']['@NotBefore'] = instant
    assertion['AuthnStatement']['@AuthnInstant'] = instant

    # not on or after/expiration time
    notonorafter = expire_time(expire_minutes)
    assertion['Subject']['SubjectConfirmation']['SubjectConfirmationData']['@NotOnOrAfter'] = notonorafter
    assertion['Conditions']['@NotOnOrAfter'] = notonorafter

    # assertion id & session index - override in caller if you want something different
    authid = newid()
    assertion['@ID'] = authid
    assertion['AuthnStatement']['@SessionIndex'] = authid

    return root


def samlErrorResponseTemplate():

    root = deepcopy(__saml_error_response_template)
    response = root['samlp:Response']

    instant = issue_instant_now()
    response['@ID'] = newid()
    response['@IssueInstant'] = instant

    return root

"""

Python dict template of a SAMLResponse in xmltodict format

    - dates are stubbed out - filled by SamlResponseTemplate()
    - id's are named identical for each group - filled by SamlResponseTemplate

    - Attribute section is empty - set this in authorization process
    - Status code is stubbed out - set in authorization process
    - request data is empty - set this in authorization process 
    - response data is stubbed out - set based on request

    - other values are static protocol defined or set to harmless defaults
"""
__saml_response_template = {
    'samlp:Response': {
        '@ID': '_id here',
        '@Version': '2.0',
        '@IssueInstant': 'issue_time_utc_iso',
        '@Destination': 'SP ACS URL',
        '@InResponseTo': '_in response to from request',
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'Issuer': {
            '@xmlns': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': 'URN of IdP'
        },
        'samlp:Status': {
            'samlp:StatusCode': {
                '@Value': '_SAML status code'
            },
            'samlp:StatusMessage':{
                '#text': ''
            }
        },
        'Assertion': {
            '@ID': '_id of assertion and session index',
            '@IssueInstant': 'issue_time_utc_iso',
            '@Version': '2.0',
            '@xmlns': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'Issuer': 'URN of IdP',
            'Subject': {
                'NameID': {
                    '@Format': 'Name ID format',
                    '#text': 'Name ID'
                },
                'SubjectConfirmation': {
                    '@Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
                    'SubjectConfirmationData': {
                        '@InResponseTo': '_in response to from request',
                        '@NotOnOrAfter': 'expire_time_utc_iso',
                        '@Recipient': 'SP ACS URL'
                    }
                }
            },
            'Conditions': {
                '@NotBefore': 'issue_time_utc_iso',
                '@NotOnOrAfter': 'expire_time_utc_iso',
                'AudienceRestriction': {
                    'Audience': 'SP URN'
                }
            },
            'AttributeStatement': {
                'Attribute': []
            },
            'AuthnStatement': {
                '@AuthnInstant': 'issue_time_utc_iso',
                '@SessionIndex': '_id of assertion and session index',
                'AuthnContext': {
                    'AuthnContextClassRef': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
                }
            }
        }
    }
}


__saml_error_response_template = {
    'samlp:Response': {
        '@ID': '_id here',
        '@Version': '2.0',
        '@IssueInstant': 'issue_time_utc_iso',
        '@InResponseTo': '_in response to from request',
        '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'Issuer': {
            '@xmlns': 'urn:oasis:names:tc:SAML:2.0:assertion',
            '#text': 'URN of IdP'
        },
        'samlp:Status': {
            'samlp:StatusCode': {
                '@Value': 'urn:oasis:names:tc:SAML:2.0:status:Requester',
            },
            'samlp:StatusMessage': {
               '#text': '_SAML status message'
            }
        }
    }
}
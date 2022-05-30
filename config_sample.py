from logging.config import dictConfig
import os

DIR=os.path.dirname(__file__)
abspath = lambda p : os.path.join(DIR,p)


logging_config = {
        'version' : 1,
    'formatters': {'default': {
        'format': '%(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
}

dictConfig(logging_config)

session_config = {
    'secret_key': b'now is the time to test this',
    'debug': True,
    'SESSION_FILE_DIR': '/var/tmp/samlidp/cache/',
    'SESSION_TYPE': 'filesystem',
    'PERMANENT_SESSION_LIFETIME' : 300,
    'SESSION_COOKIE_NAME' :'demo',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': True,

}

#
# This is a SP configuration for access to the primary 
# authenticator (Azure in this case, but it could be any SAML2 idp)
#
with open(abspath('certs/azureidp.cer'),'rb') as f:
    saml_auth_cert = f.read()

tenent_id='1234-5678-9012'  # Azure tenent ID
saml_auth_config = {
    'comment' : 'Azure AZ Enterprise Application integration',
    'idp_url': f'https://login.microsoftonline.com/{tenent_id}/saml2',
    'sp_id': 'https://idp.example.com',
    'idp_id': f'https://sts.windows.net/{tenent_id}/',
    'acs_url' : 'https://idp.examle.com/saml/acs',
    'force_reauth' : False,
    'user_attr': 'uid',
    'idp_ok': True,
    'assertions': [
        'uid', 'givenName', 'surname', 'upn', 'emailaddress', 'groups', 'suny_global_id',
        ],
    'idp_cert' : saml_auth_cert ,
}

#
# This is the configuration for our IDP, including the SPs
# it services.
# 

with open(abspath('certs/idp.example.com.crt'),'rb') as f:
    idp_cert = f.read()

with open(abspath('certs/idp.examle.com.pem'),'rb') as f:
    idp_private_key = f.read()

idp_config = {
    'entityId' : 'https://idp.example.com',
    'destination': 'https://idp.examlpe.com/saml2',
    'x509Cert' : idp_cert,
    'priv_key' : idp_private_key,
    # SP's - there can be any number of these
    'splist': [{
        'SPEntityId' : 'https://sp.example.com',
        # list of authorizes ACS URLs (fist is the default)
        'ACSList': ['https://sp.example.com/saml2/acs',],
        'RelayState':'',
        'AuthAttrs': ['uid', 'surname', 'givenname', 'groups', 'suny_global_id'],
        'NameIdAttr': 'emailaddress',
    }],
}


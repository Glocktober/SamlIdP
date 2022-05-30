from flask import Flask
from flask_session import Session
from SamlSP import SamlSP
from SamlIdP import SamlIdP

from config import session_config, idp_config, saml_auth_config

app = Flask(__name__)

app.config.from_mapping(session_config)
ses = Session(app)

auth = SamlSP(config=saml_auth_config)
app.register_blueprint(auth)

idp = SamlIdP(auth=auth, idp_config=idp_config, app=app)

if __name__ == '__main__':
    app.run(port=8001, debug=True)
    
else:
    application = app

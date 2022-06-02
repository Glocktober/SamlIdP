from base64 import b64encode, b64decode
from urllib.parse import parse_qs, quote, urlencode
from lxml import etree
import zlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from .constants import *


class   _Signer:
    """ Performs RSA Signing and/or Verification """

    def __init__(self, cert, key=None, password=None):

        if key:
            self.key = serialization.load_pem_private_key(key, password)
        else:
            # Verify only
            self.key = None

        if cert:
            self.serial_cert = serialize_cert(cert)
            self.cert = x509.load_pem_x509_certificate(cert)
            self.public_key = self.cert.public_key()


    def sign(self, data):
        """ Sign data, return signature """

        if self.key is None:
            raise Exception('Signer has no private key')

        if type(data) is str:
            data = data.encode('utf-8')

        return self.key.sign(
            data, 
            padding.PKCS1v15(), 
            hashes.SHA256()
        )


    def verify(self, signature, data):
        """ Verify Signature on data """

        if self.cert is None:
            raise Exception('Verifier has not certificate')

        self.public_key.verify(
            signature,
            data, 
            padding.PKCS1v15(), 
            hashes.SHA256()
        )
        return True


    def validateCert(self, cert):
        """ Validate the certificate matches ours """

        cert = serialize_cert(cert)
        if cert != self.serial_cert:
            raise Exception('Incorrect Certificate')
        return True


    @classmethod
    def hash(this, data):
        """ SHA256 digest of data """

        dig=hashes.Hash(hashes.SHA256())
        dig.update(data)

        return dig.finalize()


def serialize_cert(cert):
    """ Remove PEM headers and new lines """

    if type(cert) is bytes:
        cert = cert.decode()

    replacements = [
        '\r',
        '\n',
        '-----END CERTIFICATE-----',
        '-----BEGIN CERTIFICATE-----',
    ]
    for replacement in replacements:
        cert = cert.replace(replacement, '')
    return cert



class SamlRequestSerializer:
    """ Serialize and deserialize Http-REDIRECT SAMLRequests """

    def __init__(self, cert=None, key=None, password=None):
        
        if cert or key:
            # Either sign or verify
            self.signer = _Signer(cert=cert, key=key, password=password)
        
        self.signok = key is not None

        self.verifyok = cert is not None


    def serializeSamlRequest(self,samlRequest, relayState, sign=True):
        """ Creates Query String with optional Signature """

        requestb64 = b64encode(zlib.compress(samlRequest)[2:-4])

        params = {
            'SAMLRequest': requestb64,
            'RelayState': relayState,
        }
        
        if self.signok and sign:

            params['SigAlg'] = dsSigAlgValue

            signed_info = urlencode(params)

            signature = self.signer.sign(signed_info.encode('utf-8'))
        
            url_sig = quote(b64encode(signature))
        
            return signed_info + '&Signature=' + url_sig
        
        else:
            return urlencode(params)


    @classmethod
    def deserializeSamlRequest(this, request_qs):
        """ Deserialize with no verification """

        reqargs = parse_qs(request_qs, keep_blank_values=True)
        
        if 'SAMLRequest' not in reqargs:
            raise Exception('Deserialization - SAMLRequest parameter missing')
        
        # decode and deflate SAMLRequest XML        
        samlRequest = zlib.decompress(
                b64decode(reqargs['SAMLRequest'][0]),
                wbits=-15,
            ).decode()
        
        if 'RelayState' not in reqargs:
            raise Exception(f'RelayState parameter missing')
        
        relayState = reqargs['RelayState'][0] 

        return samlRequest, relayState


    def verifySamlRequest(self, request_qs):
        """ Deserialize http-REDIRECT SAMLRequest and optionally verify signature """

        reqargs = parse_qs(request_qs, keep_blank_values=True)
        
        if 'SAMLRequest' not in reqargs:
            raise Exception('verification - SAMLRequest parameter missing')

        # decode and deflate SAMLRequest XML        
        samlRequest = zlib.decompress(
                b64decode(reqargs['SAMLRequest'][0]),
                wbits=-15,
            ).decode()
        
        if 'RelayState' not in reqargs:
            raise Exception(f'RelayState parameter missing')
        
        relayState = reqargs['RelayState'][0] 
        
        if self.verifyok:
            # We only verifiy if we have a x509 certificate for this SP
        
            if 'Signature' not in reqargs:
                raise Exception('SAMLRequest is unsigned')

            signature = b64decode(reqargs['Signature'][0])

            if 'SigAlg' not in reqargs:
                raise Exception('SigAlg parameter missing')
            
            sigalg = reqargs['SigAlg'][0]

            if sigalg != dsSigAlgValue:
                raise Exception(f'Unsupported signature algorithm {sigalg}')

            signed_part = request_qs.split('&Signature')[0]

            self.signer.verify(signature, signed_part.encode('utf-8'))
            
        return samlRequest, relayState
        


class SamlResponseSigner:
    """ Sign and Verify SAMLResponse """

    def __init__(self, cert, key=None, password=None):

        self.signer = _Signer(cert=cert, key=key, password=password)

        self.parser = etree.XMLParser(remove_blank_text=True)


    def signSamlResponse(self, saml_response):
        """ Add signature to a SAMLResponse """
    
        # Get the document ID
        xmlroot = etree.XML(saml_response,parser=self.parser)
        document_id = xmlroot.attrib['ID']

        c14n_response = etree.tostring(xmlroot, method='c14n2')

        # Calculate digest on body
        digest_value = self.signer.hash(c14n_response)

        # Create <ds:SignedInfo> document with ID and calculated digest
        signed_info = self.nodeSignedInfo(document_id, digest_value)
        
        # Sign the <ds:SignedInfo> node
        signature_value = b64encode(self.signer.sign(signed_info)).decode()

        # Create full <ds:Signature> node
        signature_xml = self.nodeSignature(signed_info, signature_value)

        # Create tree of the full <ds:Signature> node
        sigroot = etree.XML(signature_xml)

        # Add this node after the <saml:Issuer> node
        self.insertAfterTag(xmlroot, sigroot, samlIssuerTag)

        # Return signed SAMLResponse
        return etree.tostring(xmlroot, xml_declaration=False)


    def verifySamlResponse(self, saml_response, noexcept=True):
        """ Verify signed SAMLResponse """

        xmlroot = etree.XML(saml_response)

        # Remove <ds:Signature> from response
        sigroot = xmlroot.find(f'./{dsSignatureTag}')
        xmlroot.remove(sigroot)

        # Calculate digest on saml_response
        c14n_response = etree.tostring(xmlroot,method='c14n2')
        hash_value = b64encode(self.signer.hash(c14n_response)).decode()
        # verify signed info
        return self.verifySignature(sigroot, hash_value, noexcept=noexcept)


    def verifySignature(self, sigroot, response_digest, noexcept=True):
        """ Verify SAMLResponse <ds:Signature> and digest """

        try:
            # Validate signing with correct certificate
            x509_cert = sigroot.find(f'.//{dsX509CertificateTag}').text
            self.signer.validateCert(x509_cert)
            
            # Get the <ds:SignedInfo> as XML
            signed_info = sigroot.find(f'./{dsSignedInfoTag}')
            
            # play games to get c14n2 of the <SignedInfo> subtree
            signed_info_xml = etree.tostring(signed_info,method='xml')
            sinforoot = etree.XML(signed_info_xml)
            signed_info_xml = etree.tostring(sinforoot, method='c14n2')
            
            # Validate the signature for <SignedInfo>
            signature_value = sigroot.find(f'.//{dsSignatureValueTag}').text
            self.signer.verify(b64decode(signature_value), signed_info_xml)
        
            # Return digest value
            hash_value = signed_info.find(f'.//{dsDigestValueTag}').text

            return hash_value == response_digest
    
        except Exception as e:
            if noexcept:
                return False
            else:
                raise e


    def insertAfterTag(self, root, elem, tag=samlIssuerTag):
        """ Insert elem after a tag """

        loc = root.index(root.find(f'./{tag}'))
        root.insert(loc+1, elem)
        
    
    def nodeSignedInfo(self, document_id, digest_value):
        """ Create XML <SignedInfo> node """

        return f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod><Reference URI="#{document_id}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>{b64encode(digest_value).decode()}</DigestValue></Reference></SignedInfo>'
        

    def nodeSignature(self, signed_info, signature_value):
        """ Create XML <Signature> node """

        return f'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signed_info}<SignatureValue>{signature_value}</SignatureValue><KeyInfo><X509Data><X509Certificate>{self.signer.serial_cert}</X509Certificate></X509Data></KeyInfo></Signature>'


    def serializeSAMLResponse(self, saml_response):
        """ Convenience routine to both sign and b64 encode a response """

        return b64encode(self.signSamlResponse(saml_response))


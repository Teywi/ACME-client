from flask import Flask
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import serialization
import os
import ssl

class HTTPS_Server:
    app = Flask(__name__)

    certificate = ""

    def __init__(self, ee_certif, inter_certif, root_certif, key_file):

        global certificate
        certificate = ee_certif+inter_certif
        

        certificate_file_path = "my_certificate.pem"

        with open(certificate_file_path, "wb") as cert_file:
            cert_file.write(ee_certif)
            cert_file.write(inter_certif)
            cert_file.write(root_certif)
        
        """ temp = 0
        with open(certificate_file_path, "rb") as test_file:
            temp = test_file.read()
        print(temp)
        print("jcrxtyguhijiytctvb") """
        ssl_context = ssl.SSLContext()
        ssl_context.load_cert_chain(certificate_file_path, key_file)
        self.ssl_context = ssl_context
    
    @app.route('/', methods=['Get'])
    def give_certificate():
        #print(certificate)
        return certificate
    
    @app.route('/', methods=['Head'])
    def tell_alive():
        return "I am running"
    
    @app.route('/shutdown', methods=['Post'])
    def shutdown():
        os._exit(0)
    

    #def run(self):
    #    self.app.run(host= "0.0.0.0", port=5001, ssl_context=self.ssl_context)

        
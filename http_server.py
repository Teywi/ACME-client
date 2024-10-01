from flask import Flask, request
import os

class HTTP_Server():
    app = Flask(__name__)

    #thumbprint = ""
    #need to make a dict
    global dict_thumbprint
    dict_thumbprint = {}
    @app.route('/receive-token', methods=['Post'])
    def get_thumbprint():
        global thumbprint
        thumbprint = request.form.get('thumbprint')
        token = request.form.get('token')
        dict_thumbprint[token] = thumbprint
        return "Token received"


    @app.route('/.well-known/acme-challenge/<token>', methods=['Get'])
    def print_token(token):
        if token in dict_thumbprint: 
            return f"{token}.{dict_thumbprint[token]}" #dict_thumbprint[token]
        else:
            return "Token not present"
    
    @app.route('/shutdown', methods=['Post'])
    def shutdown():
        os._exit(0)
        
    """ if __name__ == '__main__':
        app.run(host= "0.0.0.0", port=5002)
        print("htttttttttttttttttttp") """

#http_server = HTTP_Server()


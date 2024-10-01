from flask import Flask
import requests
from dnslib import DNSRecord, QTYPE, RCODE
import socket
import os


class Shutdown_Server():
    app = Flask(__name__)


    @app.route('/shutdown', methods=['Get'])
    def shutdown():
        print("---------------------------------------------------------------------------------------------------------------------------------------------")
        try:
            requests.post("https://0.0.0.0:5001/shutdown", verify=False)
        except Exception as e:
            print("Error sending shutdown request to server 1:", e)

        try:
            requests.post("http://0.0.0.0:5002/shutdown")
            print("we shutdown https")
        except Exception as e:
            print("Error sending shutdown request to server 2:", e)


        request = DNSRecord.question("shutdown", qtype="A")
        dns_server_address = ("0.0.0.0", 10053)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(request.pack(), dns_server_address)
        udp_socket.close()
        print("we shut down dns")

        os._exit(0)
    
    """ if __name__ == '__main__':
        app.run(host= "0.0.0.0", port=5003)
        print("shuuuuuuuuuuuuuuuutdown") """



#will need to comment
#shutdown_server = Shutdown_Server()
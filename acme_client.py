import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import json
from https_server import HTTPS_Server

import base64
import hashlib
import time

from dnslib import DNSRecord, QTYPE, RCODE
import socket

##pebble -config ./test/config/pebble-config.json

class ACME_Client:
        
    chall_id = "" 
    dir_url = ""
    domains = []
    ca_certificate = 'pebble.minica.pem'
    revoked = False
    stop = False

    def __init__(self, chall_id, dir_url, domains, revoked):
        self.chall_id = chall_id
        self.dir_url = dir_url
        print(self.dir_url)
        self.domains = domains
        self.revoked = revoked
    


    def dns_query(self, domain, dns_server_ip, dns_server_port):
        request = DNSRecord.question(domain, qtype="A")

        dns_server_address = (dns_server_ip, dns_server_port)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(request.pack(), dns_server_address)

        udp_socket.close()

    @staticmethod
    def base64_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    
    # crypto part
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    
    csr_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    

    def csr(self):
        san_list = [x509.DNSName(domain) for domain in self.domains]

        # Build the subject with the common name and add the SAN extension
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ETHZ"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.domains[0])  # Use the first domain as CN
        ])

        # Create the CSR with the SAN extension
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
            x509.SubjectAlternativeName(san_list), critical=False
        ).sign(self.csr_private_key, hashes.SHA256(), default_backend())
        return csr


    def acme_client(self):
    
        public_key = self.private_key.public_key()

        jwk_object = {
            "e": self.base64_encode(public_key.public_numbers().e.to_bytes(3, "big")),
            "kty": "RSA",
            "n": self.base64_encode(public_key.public_numbers().n.to_bytes(256, "big"))
        }
    #############
    ###########
    #######
        ##should do verify=ca_certificate
        directory = 0
        try:
            directory = requests.get(self.dir_url, verify=self.ca_certificate) #self.ca_certificate
        except Exception as e:
            self.dns_query("invalid", "0.0.0.0", 10053)
            print("got problem verifying")
            self.stop = True
            return 
        
        self.directory = directory
        if directory.status_code != 200:
            self.stop = True
            return 
        nonce_url = directory.json()['newNonce']
        self.nonce_url = nonce_url
        
        
        acc_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']
        newAccount_url = directory.json()['newAccount']
        acc_header = {
        "alg": "RS256",
        "jwk": jwk_object,
        "nonce": acc_nonce,
        "url": newAccount_url
        }
        acc_payload = {
            "termsOfServiceAgreed": True
        }
        
        newAccount_header = self.base64_encode(json.dumps(acc_header).encode('utf-8'))
        newAccount_payload = self.base64_encode(json.dumps(acc_payload).encode('utf-8'))
        
        
        newAccount_signature = self.private_key.sign(
            f"{newAccount_header}.{newAccount_payload}".encode('utf-8'),        
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        newAccount_data = {
        "protected": newAccount_header,
        "payload": newAccount_payload,
        "signature" : self.base64_encode(newAccount_signature)
        }

        content_header = {"Content-Type": "application/jose+json"}
        self.content_header = content_header
        account = requests.post(newAccount_url, json=newAccount_data, headers=content_header, verify=self.ca_certificate)
        #print(account.text)



    ##submit order
        newOrder_url = directory.json()['newOrder']
        kid = account.headers['Location']
        self.kid = kid
        newOrder_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']
        newOrd_header = {
        "alg": "RS256",
        "kid": kid,
        "nonce": newOrder_nonce,
        "url": newOrder_url
        }
        newOrder_header = self.base64_encode(json.dumps(newOrd_header).encode('utf-8'))
        identifiers = []
        for domain in self.domains:
            identifiers.append({"type": "dns", "value": domain})
        newOrd_payload = {
            "identifiers": identifiers
        }
        newOrder_payload = self.base64_encode(json.dumps(newOrd_payload).encode('utf-8'))

        newOrder_signature = self.private_key.sign(
            f"{newOrder_header}.{newOrder_payload}".encode('utf-8'),        
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        newOrder_data = {
            "protected": newOrder_header,
            "payload": newOrder_payload,
            "signature" : self.base64_encode(newOrder_signature)
        }

        newOrder = requests.post(newOrder_url, json=newOrder_data, headers=content_header, verify=self.ca_certificate)
        #print(newOrder.text)
        #newOrder.json()['finalize'] need to send a csr when challenges are completed (cf p27)

        print(newOrder.json())

    ##authorisations
        for i in range(0, len(self.domains)):
            auth_url = newOrder.json()["authorizations"][i] #i
            auth_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']

            auth_header = {
            "alg": "RS256",
            "kid": kid,
            "nonce": auth_nonce,
            "url": auth_url
            }
            auth_header = self.base64_encode(json.dumps(auth_header).encode('utf-8'))
            auth_payload = ""

            auth_signature = self.private_key.sign(
                f"{auth_header}.{auth_payload}".encode('utf-8'),        
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            auth_data = {
                "protected": auth_header,
                "payload": auth_payload,
                "signature" : self.base64_encode(auth_signature)
            }

            challenges = requests.post(auth_url, json=auth_data, headers=content_header, verify=self.ca_certificate)
            #print(challenges.text)


            """
            #do the challenge depending on whether we do dns-01 or http-01 challenge
            """

            chall_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']
            challenge_list = challenges.json()["challenges"]
            chall_url = ""
            jwk_json = json.dumps(jwk_object, separators=(',', ':')).encode('utf-8')
            thumbprint = self.base64_encode(hashlib.sha256(jwk_json).digest())   

            for chall in challenge_list:
                if chall["type"] == "dns-01" and self.chall_id == "dns01":
                    chall_url = chall["url"]
                    chall_token = chall["token"]
                    keyAuth = self.base64_encode(hashlib.sha256(f"{chall_token}.{thumbprint}".encode('utf-8')).digest())
                    domain = self.domains[i]
                    self.dns_query(f"domain.{domain}.{keyAuth}", "0.0.0.0", 10053) #change with actual domain name


                elif chall["type"] == "http-01" and self.chall_id == "http01":
                    chall_url = chall["url"]
                    chall_token = chall["token"]
                    send_token = requests.post("http://0.0.0.0:5002/receive-token", data={'thumbprint' : thumbprint, 'token' : chall_token})

            chall_header = {
                "alg": "RS256",
                "kid": kid,
                "nonce": chall_nonce,
                "url": chall_url
            }
            chall_header = self.base64_encode(json.dumps(chall_header).encode('utf-8'))
            chall_payload = self.base64_encode(json.dumps({}).encode('utf-8'))

            chall_signature = self.private_key.sign(
                f"{chall_header}.{chall_payload}".encode('utf-8'),        
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            chall_data = {
                "protected": chall_header,
                "payload": chall_payload,
                "signature" : self.base64_encode(chall_signature)
            }
            #say which challenge we've done
            updated_chall = requests.post(chall_url, json=chall_data, headers=content_header, verify=self.ca_certificate)
            print(updated_chall.text)
            
            #check if status is valid
            auth_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']
            auth_header = {
            "alg": "RS256",
            "kid": kid,
            "nonce": auth_nonce,
            "url": auth_url
            }
            auth_header = self.base64_encode(json.dumps(auth_header).encode('utf-8'))
            auth_payload = ""

            auth_signature = self.private_key.sign(
                f"{auth_header}.{auth_payload}".encode('utf-8'),        
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            auth_data = {
                "protected": auth_header,
                "payload": auth_payload,
                "signature" : self.base64_encode(auth_signature)
            }

            ##should wait for request to dns/http server before polling
            time.sleep(5)  #need to sleep otherwise no time to check
            challenges = requests.post(auth_url, json=auth_data, headers=content_header, verify=self.ca_certificate)
            print(challenges.text)

        ##end of for loop

        print("------------------------")
        print(newOrder.json())
        ##send csr to finalise url
        finalise_url = newOrder.json()['finalize']
        finalise_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']

        finalise_header = {
            "alg": "RS256",
            "kid": kid,
            "nonce": finalise_nonce,
            "url": finalise_url
        }
        finalise_header = self.base64_encode(json.dumps(finalise_header).encode('utf-8'))
        finalise_csr = self.base64_encode(self.csr().public_bytes(serialization.Encoding.DER))
        finalise_payload = {
            "csr": finalise_csr
        }
        finalise_payload = self.base64_encode(json.dumps(finalise_payload).encode('utf-8'))
        finalise_signature = self.private_key.sign(
            f"{finalise_header}.{finalise_payload}".encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        finalise_data = {
            "protected": finalise_header,
            "payload": finalise_payload,
            "signature": self.base64_encode(finalise_signature)
        }

        finalise_answer = requests.post(finalise_url, json=finalise_data, headers=content_header, verify=self.ca_certificate)

        while(True):
            checkStatus_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']
            checkStatus_url = newOrder.headers['Location']
            checkStatus_header = {
                "alg": "RS256",
                "kid": kid,
                "nonce": checkStatus_nonce,
                "url": checkStatus_url
            }
            checkStatus_header = self.base64_encode(json.dumps(checkStatus_header).encode('utf-8'))
            checkStatus_payload = ""
            checkStatus_signature = self.private_key.sign(
                f"{checkStatus_header}.{checkStatus_payload}".encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            checkStatus_data = {
                "protected": checkStatus_header,
                "payload": checkStatus_payload,
                "signature": self.base64_encode(checkStatus_signature)
            }
            
            statusAnswer = requests.post(checkStatus_url, json=checkStatus_data, headers=content_header, verify=self.ca_certificate)
            print(statusAnswer.text)
            if statusAnswer.json()["status"] == "invalid":
                break
            if statusAnswer.json()["status"] == "valid":
                break
        

        certificate_url = statusAnswer.json()["certificate"]
        certificate_nonce = requests.head(nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']

        certificate_header = {
            "alg": "RS256",
            "kid": kid,
            "nonce": certificate_nonce,
            "url": certificate_url
        }
        certificate_header = self.base64_encode(json.dumps(certificate_header).encode('utf-8'))
        certificate_payload = ""
        certificate_signature = self.private_key.sign(
            f"{certificate_header}.{certificate_payload}".encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        certificate_data = {
            "protected": certificate_header,
            "payload": certificate_payload,
            "signature": self.base64_encode(certificate_signature)
        }
        
        certificate_text = requests.post(certificate_url, json=certificate_data, headers=content_header, verify=self.ca_certificate).text
        certificates = x509.load_pem_x509_certificates(certificate_text.encode())
        der_certificate = certificates[0].public_bytes(serialization.Encoding.DER)
        self.der_certificate = der_certificate
        pem_certificate = certificates[0].public_bytes(serialization.Encoding.PEM)
        self.pem_certificate = pem_certificate
        pem_inter_certificate = certificates[1].public_bytes(serialization.Encoding.PEM)
        self.pem_inter_certificate = pem_inter_certificate
        

        csr_private_key_pem = self.csr_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        self.csr_private_key_pem = csr_private_key_pem
        
    def create_https(self):
        if self.stop:
            return
        print("Starting https server")
        key_file_path = "my_key.pem"

        root_certif = 0

        with open(self.ca_certificate, "rb") as root_file:
            root_certif = root_file.read()


        with open(key_file_path, "wb") as key_file:
            key_file.write(self.csr_private_key_pem)

        print("---------------------------")
        print(self.domains)
        https_server = HTTPS_Server(self.pem_certificate, self.pem_inter_certificate, root_certif, key_file_path)
        #https_server.run()
        return https_server
    
    def revoke_certif(self):
        if self.stop:
            return
        if self.revoked:
            print("Starting recovation")
            revoked_url = self.directory.json()['revokeCert']
            revoked_nonce = requests.head(self.nonce_url, verify=self.ca_certificate).headers['Replay-Nonce']

            revoked_header = {
                "alg": "RS256",
                "kid": self.kid,
                "nonce": revoked_nonce,
                "url": revoked_url
            }
            revoked_header = self.base64_encode(json.dumps(revoked_header).encode('utf-8'))
            revoked_payload = {
                "certificate" : self.base64_encode(self.der_certificate)
            }
            revoked_payload = self.base64_encode(json.dumps(revoked_payload).encode('utf-8'))

            revoked_signature = self.private_key.sign(
                f"{revoked_header}.{revoked_payload}".encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            revoked_data = {
                "protected" : revoked_header,
                "payload" : revoked_payload,
                "signature" : self.base64_encode(revoked_signature)
            }
            
            revoked_answer = requests.post(revoked_url, json=revoked_data, headers=self.content_header, verify=self.ca_certificate)
            print(revoked_answer)
            print("revoked")

    




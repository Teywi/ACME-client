from dnslib.server import DNSServer
from dnslib.dns import RR, TXT, QTYPE, RCODE, A
import os

class DNS_Server():
    record = ""
    
    def __init__(self, r):
        self.record = r

    
    class DNSResolver():
        record = ""

        global domain_keys
        domain_keys = {}

        def __init__(self, record):
            super().__init__()
            self.record = record

        def resolve(self, request, handler):
            reply = request.reply()
            qname = request.q.qname
            str_qname = str(qname)
            print("REQUEST:", qname)


            if str_qname.startswith("domain"): #comes from acme client
                split = str_qname.rstrip(".").split(".")
                domain_keys['.'.join(split[1:-1])] = split[-1]  #point is added at the end of a dns query
                print(domain_keys)
                #put domain in dict and the keyAuth as value
            elif str_qname.startswith("invalid"):
                self.record = ""

            elif str_qname.startswith("_acme-challenge."): #comes from acme server
                domain = str_qname.split(".", 1)[1].rstrip(".")
                if "*."+domain in domain_keys:
                    keyAuth = domain_keys["*."+domain]
                    print(keyAuth)
                    reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rdata=TXT(keyAuth.encode('utf-8'))))
                elif domain in domain_keys:
                    keyAuth = domain_keys[domain]
                    print(keyAuth)
                    reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rdata=TXT(keyAuth.encode('utf-8'))))
                else:
                    reply.header.rcode = RCODE.NXDOMAIN
            elif str_qname.startswith("shutdown"):
                os._exit(0)

            else:
                reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rdata=A(self.record)))  #should return "1.2.3.4" I think
            return reply
        
    def start_server(self):
        resolver = self.DNSResolver(self.record)
        #need to specify address = "0.0.0.0"
        udp_server = DNSServer(resolver, address="0.0.0.0", port=10053)
        udp_server.start()
        print("dnnnnnnnnnnnnnnnnnnnnnnnnnnnnns")


    

if __name__ == '__main__':
    dns_server = DNS_Server("0.0.0.0")
    dns_server.start_server()
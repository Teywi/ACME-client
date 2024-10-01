import argparse
import threading
from acme_client import ACME_Client
from http_server import HTTP_Server
from dns_server import DNS_Server
from shutdown_server import Shutdown_Server
import time

servers_ready = threading.Event()

def http_server_thread():
    http_server = HTTP_Server()
    http_server.app.run(host="0.0.0.0", port=5002)

def dns_server_thread(record):
    dns_server = DNS_Server(record)
    dns_server.start_server()

def shutdown_server_thread():
    shutdown_server = Shutdown_Server()
    shutdown_server.app.run(host="0.0.0.0", port=5003)


def acme_client_thread(record, chall_id, dir, domains, revoke):
    acme_client = ACME_Client(chall_id, dir, domains, revoke)
    acme_client.acme_client()
    def create_https():
        if not acme_client.stop:
            https_server = acme_client.create_https()
            https_server.app.run(host= record, port=5001, ssl_context=https_server.ssl_context)
    server_thread = threading.Thread(target=create_https)
    revoke_thread = threading.Thread(target=acme_client.revoke_certif)

    server_thread.start()

    time.sleep(1.5)

    revoke_thread.start()

    server_thread.join()
    revoke_thread.join()




parser = argparse.ArgumentParser()

parser.add_argument("chall_id", type=str)
parser.add_argument("--dir", type=str)
parser.add_argument("--record", type=str, )
parser.add_argument("--domain", action="append")
parser.add_argument("--revoke", action="store_true")
args = parser.parse_args()

chall_id = args.chall_id
dir = args.dir
record = args.record
domains = args.domain
revoke = args.revoke
print(chall_id)
print(dir)
print(record)
print(domains)
print(revoke)


http_thread = threading.Thread(target=http_server_thread)
dns_thread = threading.Thread(target=dns_server_thread, args=(record,))
shutdown_thread = threading.Thread(target=shutdown_server_thread)
acme_thread = threading.Thread(target=acme_client_thread, args=(record, chall_id, dir, domains,revoke, ))

http_thread.start()
dns_thread.start()
shutdown_thread.start()
time.sleep(3)
acme_thread.start()

http_thread.join()
dns_thread.join()
shutdown_thread.join()
acme_thread.join()
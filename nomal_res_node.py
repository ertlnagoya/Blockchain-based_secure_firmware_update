# !/usr/bin/env python3
# coding:utf-8

from socket import *
import os
import git
import json
import sys
from sys import argv
import urllib.request
import urllib.error
import ssl
from uuid import uuid4
from fractions import gcd


HOST = "0.0.0.0"
NOMAL_PORT = 33844
VALID_PORT = 33845

NODE_ADDRESS = 'localhost'
NODE_PORT = 5000

# For git
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test
VER = "1"
HASH = "f52d885484f1215ea500a805a86ff443"
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address for this
sender = str(uuid4()).replace('-', '')

# Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context


def git_clone():
    _repo_path = os.path.join('./', DIRECTORY)
    # clone from remote
    git_repo = git.Repo.clone_from(
        URL, _repo_path, branch='master')


def git_pull():
    repo = git.Repo(DIRECTORY)
    o = repo.remotes.origin
    o.pull()
    print(o)


def recv_until(c, delim="\n"):
    res = c.recv(1024)
    if len(res) == 0:
        return ""
    while not res[-1] == delim:
        data = c.recv(1024)
        if len(data) == 0:
            return res
        res += data
    return res


def new_transaction(address):
    address_nt = 'https://' + address + '/transactions/new'
    data_nt = {
        "counter": 1,
        # "merkle tree": ,
        "sender": sender,
        "recipient": "someone-other-address",
        # "digital signature": ,
        "verifier": HASH
    }
    headers_nt = {
        'Content-Type': 'application/json',
    }

    req = urllib.request.Request(
        address_nt, json.dumps(data_nt).encode(), headers_nt)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def mine(address):
    address_m = 'https://' + address + '/mine'
    req = urllib.request.Request(address_m)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def chain(address):
    address_c = 'https://' + address + '/chain'
    req = urllib.request.Request(address_c)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            # print(body)
            return body
    except urllib.error.HTTPError as err:
        print(err.code)
        return -1
    except urllib.error.URLError as err:
        print(err.reason)
        return -1


def resolve(address):
    address_r = 'https://' + address + '/nodes/resolve'
    req = urllib.request.Request(address_r)
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read()
            print(body)
    except urllib.error.HTTPError as err:
        print(err.code)
    except urllib.error.URLError as err:
        print(err.reason)


def transaction(address):
    print("Transaction start.")
    new_transaction(address)
    mine(address)
    # print(chain(address))
    print("Transaction finish!!")


def search_version(address):
    ver = 0
    print("[*] Search start.")
    data = json.loads(chain(address))
    print(json.dumps(data, sort_keys=True, indent=4))
    keylist = data.keys()
    # print()
    print(keylist)
    for key in data['chain']:
        count = key['index']
        for key_next in key['transactions']:
            if key_next != "[]":
                if key_next['sender'] == sender:
                    # print(key_next)
                    # print(key_next['url'])
                    # index = count
                    # print(index)
                    ver = key_next['ver']
                    # print(key_next['ver'])
    # print(ver)
    return ver

    print("[*] Search finish.")


def verify(address):
    # search
    ver = search_version(address)
    print("[*] Blockchain version: " + str(ver))


def lcm(p, q):
    return (p * q) // gcd(p, q)


def generate_keys(p, q):
    N = p * q
    L = lcm(p - 1, q - 1)
    for i in range(2, L):
        if gcd(i, L) == 1:
            E = i
            break
    for i in range(2, L):
        if (E * i) % L == 1:
            D = i
            break
    return (E, N), (D, N)


def encrypt(plain_text, public_key):
    E, N = public_key
    plain_integers = [ord(char) for char in plain_text]
    encrypted_integers = [i ** E % N for i in plain_integers]
    encrypted_text = ''.join(chr(i) for i in encrypted_integers)
    return encrypted_text


def decrypt(encrypted_text, private_key):
    D, N = private_key
    encrypted_integers = [ord(char) for char in encrypted_text]
    decrypted_intergers = [i ** D % N for i in encrypted_integers]
    decrypted_text = ''.join(chr(i) for i in decrypted_intergers)
    return decrypted_text


def tuple_key(payload):
    '''
    return public_key from payload
    '''
    data = []
    key = []
    data = payload.split("-")
    data[0] = data[0].replace('(', '')
    data[0] = data[0].replace(')', '')
    key = data[0].split(",")
    key[0] = int(key[0])
    key[1] = int(key[1])
    return tuple(key)


def randam(payload, r_before):
    '''
    return randam nuber from payload
    '''
    data = []
    data = payload.split("-")
    r = int(data[4])
    if (r_before + 2 - r) != 0:
        print("Error: Rundam nuber. It may be Reply Attack!!", r, r_before)
    # print(r)
    return r + 1


def randam_ini(payload):
    '''
    return randam nuber from payload
    '''
    data = []
    data = payload.split("-")
    r = data[4]
    return int(r) + 1


def make_payload(public_key, sender, NODE, INFO, r):
    payload = (str(public_key) + '-' + sender + '-' + NODE +
                '-' + INFO + '-' + str(r))
    return payload


# For HTTPS conection
sslctx = ssl.create_default_context()
sslctx.load_cert_chain('cert.crt', 'server_secret.key')


while True:
    if len(sys.argv) == 2:
        NOMAL_PORT = int(argv[1])
        print("[*] Port: ", NOMAL_PORT)
    else:
        print("[*] Default port:", NOMAL_PORT)
        # sys.exit()

    if os.path.isdir("./repo"):
        print("[*] already exist.")
    else:
        print("[*] make repo")
        git_clone()
    data = []
    key = []
    public_client_key = ''
    public_server_key = ''

    # RSA
    public_key, private_key = generate_keys(107, 3259)
    print("public_key:", public_key)
    print("private_key:", private_key)

    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, NOMAL_PORT))
    s.bind((HOST, NOMAL_PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)

    while True:
        # c2-1-2 & c2-2-2 & c2-3-2
        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        print("[*] Reception1: " + str(payload))
        payload = payload.decode("UTF-8")

        public_client_key = tuple_key(payload)
        print("public_client_key", key)
        # print(type(key))
        # print(tuple(public_key))
        # print(type(public_key))
        r = randam_ini(payload)
        data = payload.split("-")
        comp = int(data[3])
        if int(VER) == comp:
            print("Version check: req = res!")
            # join_verification c2-2-3
            payload = make_payload(public_key, sender, 'nomalnode', VER, r)
            print("[*] c2-2-3:send", payload)
            payload = encrypt(payload, tuple(public_client_key))
            # print(payload)
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

            # git_pull()
            address = NODE_ADDRESS + ':' + str(NODE_PORT)
            # verify(address)
            # mine(address)
            transaction(address)
            print("waiting...")
            # resolve(address)

            # Verifies and decrypts req_verification message
            # and prepares to send H(fv') c2-2-7
            payload = conn.recv(1024)
            # print("[*] Reception: " + str(payload))
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception:c2-2-7", payload)

            # c2-2-8
            r = randam(payload, r - 1)
            payload = make_payload(public_key, sender, 'nomalnode', HASH, r)
            print("[*] c2-2-8:send", payload)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

        if int(VER) < comp:
            #  Verifies notice_download message c2-1-3
            print("Version check: req > res!")
            payload = make_payload(public_key, sender, 'nomalnode', VER, r)
            print("[*] c2-1-3:send", payload)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

            # Verifies notice_download message c2-1-6
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c2-1-6", payload)
            r = randam(payload, r)

            # conn.close()
            soc = socket(AF_INET)
            soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            soc.connect((HOST, VALID_PORT))
            print("[*] connecting to %s:%s" % (HOST, VALID_PORT))

            r = randam(payload, r)
            payload = make_payload(public_key, sender, 'req_metadata', VER, r)
            soc.sendall(payload.encode("UTF-8"))
            print("[*] c2-1-7:send", payload)

            # Decrypts res_metadata message and obtains H(fvnew) from Mvnew c2-1-10
            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c2-1-10", payload)
            public_server_key = tuple_key(payload)

            # req_download c2-1-11
            r = randam(payload, r)
            payload = make_payload(public_key, sender, 'req_metadata', 'Dawnload', r)
            print("[*] c2-1-11:send", payload)
            payload = encrypt(payload, tuple(public_server_key))
            # print(payload)
            payload = payload.encode("UTF-8")
            soc.sendall(payload)

            # Downloads and installs the latest firmware file
            # after checking res_download message c2-1-14
            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)

            git_pull()

            print("[*] Reception: c2-1-14", payload)

            soc.close()

        if int(VER) > comp:
            print("Version check: req < res!")
            # res_verchk c2-3-3
            payload = make_payload(public_key, sender, 'nomalnode', VER, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

        print("[*] Finish!!")

    conn.close()

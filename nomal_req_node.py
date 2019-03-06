# !/usr/bin/env python3
# coding:utf-8

import sys
import os
import git
from sys import argv
from socket import *
import socket as Socket
from uuid import uuid4
from fractions import gcd
import random

HOST = "0.0.0.0"
NOMAL_PORT = 33844
VALID_PORT = 33845


# For git
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

# For test
VER = "2"
HASH = "f52d885484f1215ea500a805a86ff443"
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" + HASH + ";" + "len" + ";" + HOST
# "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address for this
sender = str(uuid4()).replace('-', '')


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


def make_payload(public_key, sender, NODE, INFO, r):
    payload = (str(public_key) + '-' + sender + '-' + NODE +
                '-' + INFO + '-' + str(r))
    return payload


def client(HOST, public_key, private_key):
    # Randam number
    r = random.randrange(1000)

    # conection
    soc = socket(AF_INET)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    soc.connect((HOST, NOMAL_PORT))
    print("[*] connecting to %s:%s" % (HOST, NOMAL_PORT))
    # soc.connect((HOST, VALID_PORT))
    # print("[*] connecting to %s:%s" % (HOST, VALID_PORT))
    # verbose_ping(sys.argv[12)

    # req_vercheck c1-1-1
    payload = make_payload(public_key, sender, "nomalnode", VER, r)
    soc.sendall(payload.encode("UTF-8"))
    print("[*] c1-1-1:send", payload)

    # Generates verifier H(fv) after checking res_verchk message c1-1-4
    payload = soc.recv(1024)
    payload = payload.decode("UTF-8")
    payload = decrypt(payload, private_key)
    print("[*] payload decode & decrypt: c1-1-4", payload)
    public_server_key = tuple_key(payload)
    # print("[*] public_server_key", public_server_key)

    data = payload.split("-")
    r = randam(payload, r - 1)
    comp = int(data[3])

    if str(data[2]) == "validnode":
        print("[*] Server is valid node")
        if int(VER) == comp:
            # req_verification c1-1-5
            print("[*] Version check: req = res!")
            payload = make_payload(public_key, sender, "nomalnode", HASH, r)
            payload = encrypt(payload, tuple(public_server_key))
            # print(payload)
            payload = payload.encode("UTF-8")
            soc.sendall(payload)
            print("[*] c1-1-5:send", data)

            # Verifies and decrypts res_verification message,
            # and compares H(fv) and H(fvnew c1-1-8
            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: " + str(payload))
            data = payload.split("-")
            # print("c1-1-8: " + data[3])

            if str(HASH) == str(data[3]):
                print("[*] SAME!!")
            else:
                print("[*] Download start!")
                git_pull()

        else:
            print("[*] It is not latest! Download start!")

            # req_download c1-2-5
            r = randam(payload, r)
            payload = make_payload(public_key, sender, "nomalnode", 'Download', r)
            payload = encrypt(payload, tuple(public_server_key))
            # print(payload)
            payload = payload.encode("UTF-8")
            soc.sendall(payload)

            # Downloads and installs the latest firmware file 
            # after checking res_download message c1-2-8
            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: " + str(payload))
            data = payload.split("-")
            soc.close()

            git_pull()

    if str(data[2]) == "nomalnode":
        print("[*] Server is nomal node")
        if int(VER) == comp:
            print("[*] Version check: req = res!")
            # c2-2-4
            payload = make_payload(public_key, sender, "nomalnode", HASH, r)
            print("[*] c2-2-4:send", payload)
            payload = encrypt(payload, tuple(public_server_key))
            # print(payload)
            payload = payload.encode("UTF-8")
            soc.sendall(payload)

            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: " + str(payload))
            data = payload.split("-")
            if str(HASH) == str(data[3]):
                print("[*] SAME!!")
            else:
                print("[*] Download start!")
                git_pull()

        if int(VER) < comp:
            print("[*] Version check: req < res!")
            # req_metadata c2-3-5
            soc.close()
            soc = socket(AF_INET)
            soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            soc.connect((HOST, VALID_PORT))
            print("[*] connecting to %s:%s" % (HOST, VALID_PORT))

            payload = make_payload(public_key, sender, 'req_metadata', 'metadata', r)
            print("[*] c2-3-5:send", payload)
            soc.sendall(payload.encode("UTF-8"))

            # Decrypts res_metadata message and obtains H(fvnew) from Mvnew c2-3-8
            payload = soc.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c2-3-8 ", payload)
            public_server_key = tuple_key(payload)

            #  res_download c2-3-9
            r = randam(payload, r - 1)
            payload = make_payload(public_key, sender, 'req_metadata', 'Download', r)
            print("[*] c2-3-9:send", payload)
            payload = encrypt(payload, tuple(public_server_key))
            payload = payload.encode("UTF-8")
            soc.sendall(payload)

            git_pull()

        if int(VER) > comp:
            print("[*] Version check: req > res!")
            # notice_download c2-1-5
            payload = make_payload(public_key, sender, 'omalnode', 'notice', r)
            print("[*] c2-1-5:send", payload)
            payload = encrypt(payload, tuple(public_server_key))
            payload = payload.encode("UTF-8")
            soc.sendall(payload)

    soc.close()
    print("[*] Finish!!")


if __name__ == '__main__':
    data = []
    if len(sys.argv) == 2:
        HOST = argv[1]
    else:
        if len(sys.argv) == 3:
            NOMAL_PORT = int(argv[2])
            print("[*] Port: ", NOMAL_PORT)
        else:
            print("[*] Default port:", NOMAL_PORT)
            # sys.exit()
            print("Error: ")
            sys.exit()

    if os.path.isdir("./repo"):
        print("[*] already exist.")
    else:
        print("[*] make repo")
        git_clone()

    # RSA: generate
    public_key, private_key = generate_keys(107, 3259)
    print(public_key)
    print(private_key)

    client(HOST, public_key, private_key)

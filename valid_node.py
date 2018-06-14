# !/usr/bin/env python3
# coding:utf-8

from socket import *
import os
import git
import json
import sys
import urllib.request
import urllib.error
import ssl
import requests
from uuid import uuid4
import hashlib
from fractions import gcd


HOST = "0.0.0.0"
NOMAL_PORT = 33844
VALID_PORT = 33845

# For test
VER = "1"
HASH = "f52d885484f1215ea500a805a86ff443"
URL = 'git@github.com:ertlnagoya/Update_Test.git'
FILE_NAME = 'Update_Test'
METADATA = FILE_NAME + ";" +HASH + ";" +"len" + ";" + HOST 
            # "file_name+file_hash+piece_length+valid_node_URL"
DOWNLOAD = URL + ";" + HASH  # "file_URL+file_hash+len"


# Generate a globally unique address for this
sender = str(uuid4()).replace('-', '')

# Oreore certificate
# requests.get("https://8.8.8.8", verify = False)
ssl._create_default_https_context = ssl._create_unverified_context


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
    public_client_key = ''
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
        print("Error: Rundam nuber. It may be Reply Attack!!", r , r_before)
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
    payload = (str(public_key) + '-' + sender + '-' + NODE + '-' 
                + INFO + '-' + str(r))
    return payload

# For HTTPS conection
#sslctx = ssl.create_default_context()
#sslctx.load_cert_chain('cert.crt', 'server_secret.key')


while True:
    data = []
    key = []
    public_client_key = ''
    
    if len(sys.argv) == 2:
        VALID_PORT = argv[1]
        print("[*] Port: ", VALID_PORT)
    else:
        print("[*] Default port:", VALID_PORT)
        # sys.exit()

    # RSA
    public_key, private_key = generate_keys(101, 3259)
    print("public_key:", public_key)
    print("private_key:", private_key)

    # conection
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, VALID_PORT))
    s.bind((HOST, VALID_PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)

    while True:
        # Obtains vnew and Mvnew from its database c1-1-2
        payload = conn.recv(1024)
        if len(payload) == 0:
            break
        print("[*] Reception1: " + str(payload))
        payload = payload.decode("UTF-8")

        public_client_key = tuple_key(payload)
        print("public_client_key", public_client_key)
        # print(type(key))
        # print(tuple(public_key))
        # print(type(public_key))

        r = randam_ini(payload)
        data = payload.split("-")

        if str(data[2]) == "nomalnode":
            #  res_verchk c1-1-3
            payload = make_payload(public_key, sender, 'validnode', VER, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)  

            # Verifies and decrypts req_download message, and checks H(fvnew) c1-1-6
            payload = conn.recv(1024)
            if len(payload) == 0:
                break
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c1-1-6", payload)

            # es_download c1-1-7
            r = randam(payload, r)
            payload = make_payload(public_key, sender, 'validnode', HASH, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)

        if str(data[2]) == "req_metadata":
            #  Obtains Mvnew from its database c2-1-8 & c2-3-6

            #  res_metadata c2-1-9 & c2-3-7
            payload = make_payload(public_key, sender, 'validnode', METADATA, r)
            print("[*] c2-1-9 & c2-3-7:send", payload) 
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload) 

            # Verifies and decrypts req_download message, and checks H(fvnew) 
            # c2-1-12 & c2-3-10
            payload = conn.recv(1024)
            payload = payload.decode("UTF-8")
            payload = decrypt(payload, private_key)
            print("[*] Reception: c2-1-12 or c2-3-10", payload)

            # Downloads and installs the latest firmware file 
            # after checking res_download message c2-1-13 & c2-3-11
            
            # TODO peer list making

            r = randam(payload, r - 1)
            payload = make_payload(public_key, sender, 'validnode',HASH, r)
            payload = encrypt(payload, tuple(public_client_key))
            payload = payload.encode("UTF-8")
            conn.sendall(payload)
        print("[*] Finish!!")

    conn.close()
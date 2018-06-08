# !/usr/bin/env python3
# coding:utf-8

from socket import *
import os
import git
import json
import urllib.request
import urllib.error
import ssl
import requests
from uuid import uuid4
import hashlib

# debug
import random

HOST = "0.0.0.0"
PORT = 33844

NODE_ADDRESS = 'localhost'
NODE_PORT = 5000
URL = 'git@github.com:ertlnagoya/Update_Test.git'
DIRECTORY = 'repo'

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
        "sender": sender,
        "recipient": "someone-other-address",
        "ver": random.randrange(10),
        "url": URL
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

'''
def search(arg, cond):
    res = []
    if cond(arg):
        res.append(arg)
    if isinstance(arg, list):
        for item in arg:
            res += search(item, cond)
            print(res)
    elif isinstance(arg, dict):
        for value in arg.values():
            res += search(value, cond)
            print(res)
    return res


def has_star_key(arg):
    if isinstance(arg, dict):
        return arg.keys() == {"chain"}


def get_star(arg):
    return search(arg, has_star_key)
'''

def search_version(address):
    ver = 0
    print("[*] Search start.")
    data = json.loads(chain(address))
    print(json.dumps(data, sort_keys = True, indent = 4))
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
                    index = count
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
    
# For HTTPS conection
sslctx = ssl.create_default_context()
sslctx.load_cert_chain('cert.crt', 'server_secret.key')


while True:
    if os.path.isdir("./repo"):
        print("[*] already exist.")
    else:
        print("[*] make repo")
        # git_clone()
    s = socket(AF_INET)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("[*] waiting for connection at %s:%s" % (HOST, PORT))
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[*] connection from: %s:%s" % addr)
    while True:
        payload = recv_until(conn)
        if len(payload) == 0:
            break
        print("[*] Reception: " + str(payload))
        git_pull()
        address = NODE_ADDRESS + ':' + str(NODE_PORT)
        verify(address)
        # mine(address)
        transaction(address) 
        # print("waiting...")
        resolve(address)
    conn.close()

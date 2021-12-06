import urllib.request
import json
import asyncio
from icmplib import traceroute, async_multiping
import time
from datetime import datetime as dt
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, Box, PublicKey
from nacl.signing import SigningKey, SignedMessage
import nacl.secret
import nacl.utils
from os.path import exists
import struct
import sys
import requests
from flask import Flask, jsonify
import logging


logging.basicConfig(filename='client.log', level=logging.DEBUG)
# network name
writer_ip = "127.0.0.1"
#writer_ip = "155.138.230.113"
writer_port = "5000"

def get_credentials():
    creds_path = "./credentials.json"
    if(exists(creds_path)):
        with open(creds_path) as json_file:
            creds = json.load(json_file)
            return creds
    else:
        encryptionPrivateKey = PrivateKey.generate()
        encryptionPrivateKeyHex = encryptionPrivateKey.encode(encoder=HexEncoder).decode('utf-8')
        encryptionPublicKey = encryptionPrivateKey.public_key
        encryptionPublicKeyHex = encryptionPublicKey.encode(encoder=HexEncoder).decode('utf-8')

        print("secret box key size = " + str(nacl.secret.SecretBox.KEY_SIZE))
        encryptionSymmetricKey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        print("size of esk is " + str(sys.getsizeof(encryptionSymmetricKey)))
        encryptionSymmetricKeyHex = encryptionSymmetricKey.hex()

        signingPrivateKey = SigningKey.generate()
        signingPrivateKeyHex = signingPrivateKey.encode(encoder=HexEncoder).decode('utf-8')
        verifySignatureKey = signingPrivateKey.verify_key
        verifySignatureKeyHex = verifySignatureKey.encode(encoder=HexEncoder).decode('utf-8')

        credentials = {
            'encryptionPrivateKey': encryptionPrivateKeyHex,
            'encryptionPublicKey': encryptionPublicKeyHex,
            'encryptionSymmetricKey': encryptionSymmetricKeyHex,
            'signingPrivateKey': signingPrivateKeyHex,
            'verifySignatureKey': verifySignatureKeyHex
        }
        with open(creds_path, 'w') as f:
            json.dump(credentials, f)
    return credentials

def get_targets():
    with urllib.request.urlopen("http://" + writer_ip + ":" + writer_port + "/targets") as url:
        data = json.loads(url.read().decode())
    return data

targets = get_targets()
external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
credentials = get_credentials()

def get_last(ping):
    logging.debug('POSTing the following to /last_ping: ' + str(ping))
    r = requests.post("http://" + writer_ip + ":" + writer_port + "/get_last", json=ping)
    if r.ok:
        logging.debug('Received the following from /last_ping: ' + str(r.json()))
        return r.json()
    else:
        return jsonify("bad response from validator")

def get_location(ip):
    print("ip is " + ip)
    r = requests.post("http://" + writer_ip + ":" + writer_port + "/location", json=json.dumps(ip))
    if r.ok:
        return r.json()
    else:
        exit()

def write_results(host):
    ts = int(time.time())
    #rtt_bytes = struct.pack('<f', host.max_rtt)
    #box = nacl.secret.SecretBox(asymmetricKeyBytes)
    #encrypted = box.encrypt(rtt_bytes)

    location = get_location(external_ip)

    ping = {
        "src_ip": external_ip,
        "dest_ip": host.address,
        "client": "python 0.1",
        "rtt": host.max_rtt,
        "long": location["long"],
        "lat": location["lat"],
        "epoch_ts": ts,
        "miner_id": credentials["verifySignatureKey"]
        #"hops": trace
    }

    last_ping = get_last(ping)
    # sign the ping and put in the dict
    signing_key_loaded = nacl.signing.SigningKey(credentials["signingPrivateKey"], encoder=nacl.encoding.HexEncoder)
    signed_with_loaded_hex = signing_key_loaded.sign(json.dumps(last_ping).encode('utf-8'), encoder=HexEncoder).decode("utf-8")
    ping["signed_last_event"] = signed_with_loaded_hex
    logging.debug('POSTing the following event of size ' + str(sys.getsizeof(ping)) + ' bytes to /events: ' + str(ping))
    r = requests.post("http://" + writer_ip + ":" + writer_port + "/events", json=ping)

    if r.ok:
        print("Event landed: " + str(ping))
    else:
        print("bad response from validator")

async def are_alive(ips):
    hosts = await async_multiping(ips, timeout=2, count=1, privileged=False)
    for host in hosts:
        write_results(host)
    time.sleep(10)

def main():
    # get creds
    # get target list
    # run pings
    # write results

    while(1):
        asyncio.run(are_alive(targets))

if __name__ == "__main__":
    main()
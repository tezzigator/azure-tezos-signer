#!/usr/bin/env python3

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
# most of this was written by Carl/Luke Youngblood
# of Blockscale, for the AWS HSM signer
# I adapted it for MS Azure CloudHSM
###########################################################

from flask import Flask, request, Response, json, jsonify
from src.remote_signer import RemoteSigner
from logging import warning, info, basicConfig, INFO, error
from azure.keyvault import KeyVaultClient
from msrestazure.azure_active_directory import MSIAuthentication
from hashlib import blake2b, sha256
from base58check import b58encode
from uuid import uuid4
import socket

P2PK_MAGIC = bytes.fromhex('03b28b7f') #unpack('>L', b'\x03\xb2\x8b\x7f')[0]
P2HASH_MAGIC = bytes.fromhex('06a1a4') #unpack('>L', b'\x00\x06\xa1\xa4')[0]

basicConfig(filename='./remote-signer.log', format='%(asctime)s %(message)s', level=INFO)

app = Flask(__name__)

config = {
    'kv_name_domain': 'tezzigator',  # this name to be used for the vault domain
    'node_addr': 'http://127.0.0.1:8732',
    'keys': {},  # to be auto-populated
    'bakerid': socket.getfqdn() + '_' + str(uuid4())
}

kvclient = KeyVaultClient(MSIAuthentication(resource='https://vault.azure.net'))
keys = kvclient.get_keys(kvurl)
for key in keys:
    keyname = key.kid.split('/')
    keydat = kvclient.get_key(kvurl, keyname[-1], '').key

    parity = bytes([2])
    if int.from_bytes(keydat.y, 'big') % 2 == 1:
        parity = bytes([3])
    shabytes = sha256(sha256(P2PK_MAGIC + parity + keydat.x).digest()).digest()[:4]
    public_key = b58encode(P2PK_MAGIC + parity + keydat.x + shabytes).decode()
    blake2bhash = blake2b(parity + keydat.x, digest_size=20).digest()
    shabytes = sha256(sha256(P2HASH_MAGIC + blake2bhash).digest()).digest()[:4]
    pkhash = b58encode(P2HASH_MAGIC + blake2bhash + shabytes).decode()

    config['keys'].update({pkhash:{'kv_keyname':keyname[-1], 'public_key':public_key}})
    info('retrieved key info: kevault keyname: ' + keyname[-1] + ' pkhash: ' + pkhash + ' - public_key: ' + public_key)

    
@app.route('/keys/<key_hash>', methods=['POST'])
def sign(key_hash):
    p2sig=''
    response = None
    try:
        data = request.get_json(force=True)
        if key_hash in config['keys']:
            info('Found key_hash {} in config'.format(key_hash))
            key = config['keys'][key_hash]
            kvclient = KeyVaultClient(MSIAuthentication(resource='https://vault.azure.net'))
            info('Calling remote-signer method {}'.format(data))
            p2sig = RemoteSigner(kvclient, key['kv_keyname'], config, data).sign()
            response = jsonify({'signature': p2sig})
            info('Response is {}'.format(response))
        else:
            warning("Couldn't find key {}".format(key_hash))
            response = Response('Key not found', status=404)
    except Exception as e:
        data = {'error': str(e)}
        error('Exception thrown during request: {}'.format(str(e)))
        response = app.response_class(
            response=json.dumps(data),
            status=500,
            mimetype='application/json'
        )
    info('Returning flask response {}'.format(response))
    return response


@app.route('/keys/<key_hash>', methods=['GET'])
def get_public_key(key_hash):
    response = None
    try:
        if key_hash in config['keys']:
            key = config['keys'][key_hash]
            response = jsonify({
                'public_key': key['public_key']
            })
            info('Found key name {} - public_key {} for  hash {}'.format(key['kv_keyname'], key['public_key'], key_hash))
        else:
            warning("Couldn't find key info for pk_hash {}".format(key_hash))
            response = Response('Key not found', status=404)
    except Exception as e:
        data = {'error': str(e)}
        error('Exception thrown during request: {}'.format(str(e)))
        response = app.response_class(
            response=json.dumps(data),
            status=500,
            mimetype='application/json'
        )
    info('Returning flask response {}'.format(response))
    return response


@app.route('/authorized_keys', methods=['GET'])
def authorized_keys():
    return app.response_class(
        response=json.dumps({}),
        status=200,
        mimetype='application/json'
    )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=False)

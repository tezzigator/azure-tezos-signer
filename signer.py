#!/usr/bin/env python3

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
# most of this was actually written by Carl/Luke Youngblood
# of Blockscale, I just adapted it for MS Azure CloudHSM
###########################################################

from flask import Flask, request, Response, json, jsonify
from src.remote_signer import RemoteSigner
from os import environ
from logging import warning, info, basicConfig, INFO, error
from azure.keyvault import KeyVaultClient
from msrestazure.azure_active_directory import MSIAuthentication
from hashlib import sha256, blake2b
from base58 import b58encode

basicConfig(filename='./remote-signer.log', format='%(asctime)s %(message)s', level=INFO)

charenc = 'utf-8'
p2pk_magic =  bytes([3, 178, 139, 127])
p2hash_magic = bytes([6, 161, 164])

app = Flask(__name__)

# sample config
config = {
    'kv_name_domain': 'tezzigator',
    'node_addr': 'http://127.0.0.1:8732',
    'keys': { 'tz3WaftwYXHatT1afD3XfAoaXcqKRuk2J4h9': { 'public_key': 'p2pk67ZmuqaUEamAyJsMWKSFwaWeEEe2nU2bnSrQcbyrH1h7Ub7uVpt' } },
    'cosmos_host': 'https://localhost:8081',
    'cosmos_pkey': 'C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==',
    'cosmos_db': 'signeditems',
    'cosmos_collection': 'signeditems',
    'bakerid': environ['TEZOSBAKERID']
}

if 'TEZOSBAKERID' in environ: # CRITICAL that different baker machines have different IDs
    info('envar TEZOSBAKERID detected: ' + environ['TEZOSBAKERID'])
else:
    print('envar TEZOSBAKERID not set!  exiting!')
    info('envar TEZOSBAKERID not set!  exiting!')
    sys.exit(os.EX_NOTFOUND)

@app.route('/keys/<key_hash>', methods=['POST'])
def sign(key_hash):
    p2sig=''
    response = None
    try:
        data = request.get_json(force=True)
        if key_hash in config['keys']:
            info('Found key_hash {} in config'.format(key_hash))
            kvclient = KeyVaultClient(MSIAuthentication(resource='https://vault.azure.net'))
            info('Calling remote-signer method {}'.format(data))
            p2sig = RemoteSigner(kvclient, config, data).sign()
            response = jsonify({
                'signature': p2sig
            })
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
    if p2sig == 'p2sig':
        response = Response('Conflict - Already Baked', status=409)

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
            info('Found public key {} for key hash {}'.format(key['public_key'], key_hash))
        else:
            warning("Couldn't public key for key hash {}".format(key_hash))
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

@app.route('/getkey', methods=['GET'])
def getkey():
    kvclient = KeyVaultClient(MSIAuthentication(resource='https://vault.azure.net'))
    kvurl = 'https://' + config['kv_name_domain'] + '.vault.azure.net'
    keydat = kvclient.get_key(kvurl, config['kv_name_domain'], '').key

    parity = bytes([2])
    if int.from_bytes(keydat.y, 'big') % 2 == 1:
        parity = bytes([3])

    # generate p256 public key
    pubkey = parity + keydat.x

    # double hash the public key with the prefix
    hash = sha256(sha256(p2pk_magic + pubkey).digest()).digest()[:4]

    # generic blake2b hash for the shorter pkhash
    genhash = blake2b(pubkey, digest_size=20).digest()

    # double hash the genhash with the pkhash prefix
    hashpkh = sha256(sha256(p2hash_magic + genhash).digest()).digest()[:4]

    info('pubkey: ' + b58encode(p2pk_magic + pubkey + hash).decode(charenc) + '\npkhash: ' + b58encode(
        p2hash_magic + genhash + hashpkh).decode(charenc))

    return app.response_class(
        response=json.dumps({}),
        status=200,
        mimetype='application/json'
    )


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
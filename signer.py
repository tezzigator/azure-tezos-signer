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
from logging import warning, info, basicConfig, INFO
from requests import get
from json import loads

basicConfig(filename='./remote-signer.log', format='%(asctime)s %(message)s', level=INFO)

app = Flask(__name__)

# sample config
config = {
    'token_url': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net',
    'kid_url': 'https://X.vault.azure.net/keys/X',
    'node_addr': 'http://127.0.0.1:8732',
    'aad_token': '', # we will fetch this in a bit
    'keys': { 'tz3WaftwYXHatT1afD3XfAoaXcqKRuk2J4h9': { 'public_key': 'p2pk67ZmuqaUEamAyJsMWKSFwaWeEEe2nU2bnSrQcbyrH1h7Ub7uVpt' } },
    'cosmos_host': 'https://localhost:8081',
    'cosmos_pkey': 'C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==',
    'cosmos_db': 'tezzigator',
    'cosmos_collection': 'signeditems',
    'bakerid': environ['TEZOSBAKERID']
}

def get_token():
    # get bearer auth token from AAD
    info('fetching bearer token... ')
    reqheaders = {'Metadata': 'true', 'Accept': 'application/json'}
    response = get(config['token_url'], allow_redirects=False, headers=reqheaders)
    info('...got token')
    return(loads(response.text)['access_token'])

if 'TEZOSBAKERID' in environ:
    info('envar TEZOSBAKERID detected: ' + environ['TEZOSBAKERID'])
else:
    print('envar TEZOSBAKERID not set!  exiting!')
    info('envar TEZOSBAKERID not set!  exiting!')
    sys.exit(os.EX_NOTFOUND)

@app.route('/keys/<key_hash>', methods=['POST'])
def sign(key_hash):
    response = None
    try:
        data = request.get_json(force=True)
        if key_hash in config['keys']:
            info('Found key_hash {} in config'.format(key_hash))
            key = config['keys'][key_hash]
            config['aad_token'] = get_token()
            info('Calling remote-signer method {}'.format(data))
            rs = RemoteSigner(config, data)
            p2sig = rs.sign(config)
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


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
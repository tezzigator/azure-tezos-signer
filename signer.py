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
from os import path, environ
import logging
from time import gmtime, asctime, time
from requests import get, post
from json import loads

logging.basicConfig(filename='./remote-signer.log', format='%(asctime)s %(message)s', level=logging.INFO)

app = Flask(__name__)

# sample config used for testing
config = {
    'token_url': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net',
    'kid_url = 'https://<keyvaultdomainhostname>.vault.azure.net/keys/<keyname>/<keyversion>',
    'node_addr': 'http://127.0.0.1:8732',
    'aad_token': '', # we will fetch this in a bit
    'keys': { 'tz3WaftwYXHatT1afD3XfAoaXcqKRuk2J4h9': { 'public_key': 'p2pk67ZmuqaUEamAyJsMWKSFwaWeEEe2nU2bnSrQcbyrH1h7Ub7uVpt' } }
}

def get_token():
    # get bearer auth token from AAD
    logging.info('fetching bearer token... ')
    reqheaders = {'Metadata': 'true', 'Accept': 'application/json'}
    response = get(config['token_url'], allow_redirects=False, headers=reqheaders)
    logging.info('...got token')
    return(loads(response.text)['access_token'])

logging.info('loading initial token...')
config['aad_token'] = get_token()
logging.info('...got token')


@app.route('/keys/<key_hash>', methods=['POST'])
def sign(key_hash):
    response = None
    try:
        data = request.get_json(force=True)
        if key_hash in config['keys']:
            logging.info('Found key_hash {} in config'.format(key_hash))
            key = config['keys'][key_hash]
            config['aad_token'] = get_token()
            logging.info('Attempting to sign {}'.format(data))
            rs = RemoteSigner(config, data)
            response = jsonify({
                'signature': rs.sign(config)
            })
            logging.info('Response is {}'.format(response))
        else:
            logging.warning("Couldn't find key {}".format(key_hash))
            response = Response('Key not found', status=404)
    except Exception as e:
        data = {'error': str(e)}
        logging.error('Exception thrown during request: {}'.format(str(e)))
        response = app.response_class(
            response=json.dumps(data),
            status=500,
            mimetype='application/json'
        )
    logging.info('Returning flask response {}'.format(response))
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
            logging.info('Found public key {} for key hash {}'.format(key['public_key'], key_hash))
        else:
            logging.warning("Couldn't public key for key hash {}".format(key_hash))
            response = Response('Key not found', status=404)
    except Exception as e:
        data = {'error': str(e)}
        logging.error('Exception thrown during request: {}'.format(str(e)))
        response = app.response_class(
            response=json.dumps(data),
            status=500,
            mimetype='application/json'
        )
    logging.info('Returning flask response {}'.format(response))
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

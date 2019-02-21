#!/usr/bin/env python3

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
# most of this was actually written by Carl/Luke Youngblood
# of Blockscale, I just adapted it for MS Azure CloudHSM
###########################################################

from struct import unpack
from string import hexdigits
from src.tezos_rpc_client import TezosRPCClient
from binascii import unhexlify
from bitcoin import bin_to_b58check
from hashlib import blake2b
from base64 import urlsafe_b64encode, urlsafe_b64decode
from logging import info, error
from requests import post
from json import loads
import azure.cosmos.cosmos_client as cosmos_client

class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    GENERIC_PREAMBLE = 3
    LEVEL_THRESHOLD: int = 120
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, config, payload='', rpc_stub=None):
        self.keys = config['keys']
        self.payload = payload
        info('Verifying payload')
        self.data = self.decode_block(self.payload)
        info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.node_addr = config['node_addr']

    @staticmethod
    def valid_block_format(blockdata):
        return all(c in hexdigits for c in blockdata)

    @staticmethod
    def decode_block(data):
        return RemoteSigner.valid_block_format(data) and bytes.fromhex(data)

    def is_block(self):
        return self.data and list(self.data)[0] == self.BLOCK_PREAMBLE

    def is_endorsement(self):
        return list(self.data)[0] == self.ENDORSEMENT_PREAMBLE

    def is_generic(self):
        return list(self.data)[0] == self.GENERIC_PREAMBLE

    def get_block_level(self):
        level = -1
        if self.is_block():
            hex_level = self.payload[10:18]
        else:
            hex_level = self.payload[-8:]
        level = unpack('>L', unhexlify(hex_level))[0]
        info('Block level is {}'.format(level))
        return level

    def is_within_level_threshold(self):
        rpc = self.rpc_stub or TezosRPCClient(node_url=self.node_addr)
        current_level = rpc.get_current_level()
        payload_level = self.get_block_level()
        if self.is_block():
            within_threshold = current_level < payload_level <= current_level + self.LEVEL_THRESHOLD
        else:
            within_threshold = current_level - self.LEVEL_THRESHOLD <= payload_level <= current_level + self.LEVEL_THRESHOLD
        if within_threshold:
            info('Level {} is within threshold of current level {}'.format(payload_level, current_level))
        else:
            error('Level {} is not within threshold of current level {}'.format(payload_level, current_level))
        return within_threshold

    @staticmethod
    def b58encode_signature(sig):
        return bin_to_b58check(sig, magicbyte=RemoteSigner.P256_SIGNATURE)

    def sign(self, config, test_mode=False):
        encoded_sig = ''
        data_to_sign = self.payload
        info('sign() function in remote_signer now has its data to sign')
        if self.valid_block_format(data_to_sign):
            info('Block format is valid')
            if self.is_block() or self.is_endorsement() or self.is_generic():
                info('Preamble is valid.. if bake or endorse, will attempt CosmosDB level lock')
                if ((self.is_block() or self.is_endorsement()) and self.is_within_level_threshold()) or (not self.is_block() and not self.is_endorsement()):
                    try:
                        base64hash = urlsafe_b64encode(blake2b(unhexlify(data_to_sign), digest_size=32).digest()).decode('utf-8')
                        post_payload = {'alg': 'ES256', 'value': base64hash}
                        post_headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + config['aad_token']}

                        if self.is_block() or self.is_endorsement():
                            client = cosmos_client.CosmosClient(url_connection=config['cosmos_host'], auth={'masterKey': config['cosmos_pkey']})
                            collection_link = 'dbs/' + config['cosmos_db'] + ('/colls/' + config['cosmos_collection']).format(id)
                            container = client.ReadContainer(collection_link)
                            if self.is_block():
                                client.CreateItem(container['_self'], {
                                    'itemtype': 'block',
                                    'blocklevel': self.get_block_level(),
                                    'baker': config['bakerid']
                                })
                            else:
                                client.CreateItem(container['_self'], {
                                    'itemtype': 'endorse',
                                    'blocklevel': self.get_block_level(),
                                    'baker': config['bakerid']

                                })

                        info('About to sign with HSM client.')
                        response = post(config['kid_url'] + '/sign?api-version=7.0', allow_redirects=False, json=post_payload, headers=post_headers)
                        info('Signer returns HTTP data:')
                        info(response)
                        info(response.headers)
                        info(response.text)
                        base64sig = loads(response.text)['value']
                        sig = urlsafe_b64decode(base64sig + "=" * ((4 - len(base64sig) % 4) % 4))
                        encoded_sig = RemoteSigner.b58encode_signature(sig)
                        info('Base58-encoded signature: {}'.format(encoded_sig))

                    except:
                        info('could not lock level, another baker must have taken it.  OR if not CosmosDB issue, a HSM issue.')
                        encoded_sig = 'p2sig'

                else:
                    error('Invalid level')
                    raise Exception('Invalid level')
            else:
                error('Invalid preamble')
                raise Exception('Invalid preamble')
        else:
            error('Invalid payload')
            raise Exception('Invalid payload')

        return encoded_sig
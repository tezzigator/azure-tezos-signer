#!/usr/bin/env python3

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
# most of this was actually written by Carl/Luke Youngblood
# of Blockscale, I just adapted it for MS Azure CloudHSM
###########################################################

import struct
import string
from src.tezos_rpc_client import TezosRPCClient
from binascii import unhexlify
from os import environ
from bitcoin import bin_to_b58check
from hashlib import blake2b
from base64 import urlsafe_b64encode, urlsafe_b64decode
import logging
from requests import post
from json import loads

class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    GENERIC_PREAMBLE = 3
    LEVEL_THRESHOLD: int = 120
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = struct.unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, config, payload='', rpc_stub=None):
        self.keys = config['keys']
        self.payload = payload
        logging.info('Verifying payload')
        self.data = self.decode_block(self.payload)
        logging.info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.node_addr = config['node_addr']

    @staticmethod
    def valid_block_format(blockdata):
        return all(c in string.hexdigits for c in blockdata)

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
        level = struct.unpack('>L', unhexlify(hex_level))[0]
        logging.info('Block level is {}'.format(level))
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
            logging.info('Level {} is within threshold of current level {}'.format(payload_level, current_level))
        else:
            logging.error('Level {} is not within threshold of current level {}'.format(payload_level, current_level))
        return within_threshold

    @staticmethod
    def b58encode_signature(sig):
        return bin_to_b58check(sig, magicbyte=RemoteSigner.P256_SIGNATURE)

    def sign(self, config, test_mode=False):
        encoded_sig = ''
        data_to_sign = self.payload
        logging.info('About to sign')
        if self.valid_block_format(data_to_sign):
            logging.info('Block format is valid')
            if self.is_block() or self.is_endorsement()  or self.is_generic():
                logging.info('Preamble is valid')
                if self.is_within_level_threshold():
                    logging.info('Block level is valid')
                    if test_mode:
                        return self.TEST_SIGNATURE
                    else:
                        logging.info('About to sign with HSM client.')
                        base64hash = urlsafe_b64encode(blake2b(unhexlify(data_to_sign), digest_size=32).digest()).decode('utf-8')
                        post_payload = {'alg': 'ES256', 'value': base64hash}
                        post_headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': 'Bearer ' + config['aad_token']}
                        response = post(config['kid_url'] + '/sign?api-version=7.0', allow_redirects=False, json=post_payload, headers=post_headers)
                        logging.info('Signer returns HTTP data:')
                        logging.info(response)
                        logging.info(response.headers)
                        logging.info(response.text)
                        base64sig = loads(response.text)['value']
                        sig = urlsafe_b64decode(base64sig + "=" * ((4 - len(base64sig) % 4) % 4))
                        encoded_sig = RemoteSigner.b58encode_signature(sig)
                        logging.info('Base58-encoded signature: {}'.format(encoded_sig))
                else:
                    logging.error('Invalid level')
                    raise Exception('Invalid level')
            else:
                logging.error('Invalid preamble')
                raise Exception('Invalid preamble')
        else:
            logging.error('Invalid payload')
            raise Exception('Invalid payload')
        return encoded_sig

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
from logging import info, error
import azure.cosmos.cosmos_client as cosmos_client

class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    GENERIC_PREAMBLE = 3
    LEVEL_THRESHOLD: int = 120
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, kvclient, config, payload='', rpc_stub=None):
        self.payload = payload
        info('Verifying payload')
        self.data = self.decode_block(self.payload)
        info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.kvclient = kvclient
        self.config = config

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
        rpc = self.rpc_stub or TezosRPCClient(node_url=self.config['node_addr'])
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

    def sign(self, test_mode=False):
        encoded_sig = ''
        info('sign() function in remote_signer now has its data to sign')
        if self.valid_block_format(self.payload):
            info('Block format is valid')
            if self.is_block() or self.is_endorsement() or self.is_generic():  # here is where to restrict transactions
                info('Preamble is valid.')
                if ((self.is_block() or self.is_endorsement()) and self.is_within_level_threshold()) or (not self.is_block() and not self.is_endorsement()):
                    info('The request is valid.. getting signature')
                    try:
                        op = blake2b(unhexlify(self.payload), digest_size=32).digest()
                        kvurl = 'https://' + self.config['kv_name_domain'] + '.vault.azure.net'
                        sig = self.kvclient.sign(kvurl, self.config['kv_name_domain'], '', 'ES256', op).result
                        encoded_sig = RemoteSigner.b58encode_signature(sig)
                        info('Base58-encoded signature: {}'.format(encoded_sig) + ' writing DB row if bake or endorse')

                        if self.is_block() or self.is_endorsement():
                            dbclient = cosmos_client.CosmosClient(url_connection=self.config['cosmos_host'], auth={'masterKey': self.config['cosmos_pkey']})
                            collection_link = 'dbs/' + self.config['cosmos_db'] + ('/colls/' + self.config['cosmos_collection']).format(id)
                            container = dbclient.ReadContainer(collection_link)
                            # CRITICAL to have the CosmosDB set up with STRONG consistency as default model
                            # One of the next 2 (the block or endorse if/else) will be entered into the DB, if fails, then
                            # it means another baker already wrote the row.
                            if self.is_block():
                                dbclient.CreateItem(container['_self'], {
                                    'itemtype': 'block', #CRITICAL - this string 'itemtype' VERBATIM should be set as partition key in the CosmosDB SQL table
                                    'blocklevel': self.get_block_level(), # critical this set as unique key in the CosmosDB table
                                    'baker': self.config['bakerid'],
                                    'sig': encoded_sig
                                })
                            else:
                                dbclient.CreateItem(container['_self'], {
                                    'itemtype': 'endorse', #CRITICAL - this string 'itemtype' VERBATIM should be set as partition key in the CosmosDB SQL table
                                    'blocklevel': self.get_block_level(), # critical this set as unique key in the CosmosDB table
                                    'baker': self.config['bakerid'],
                                    'sig': encoded_sig
                                })
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
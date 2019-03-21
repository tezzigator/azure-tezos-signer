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
from hashlib import blake2b, sha256
from base58check import b58encode
from logging import info, error
import azure.cosmos.cosmos_client as cosmos_client

class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    GENERIC_PREAMBLE = 3
    LEVEL_THRESHOLD: int = 120
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = bytes.fromhex('36f02c34') #unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, kvclient, kv_keyname, config, payload='', rpc_stub=None):
        self.payload = payload
        info('Verifying payload')
        self.data = self.decode_block(self.payload)
        info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.kvclient = kvclient
        self.kv_keyname = kv_keyname
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
        #return bin_to_b58check(sig, magicbyte=RemoteSigner.P256_SIGNATURE)
        blake2bhash = blake2b(sig, digest_size=32).digest()
        shabytes = sha256(sha256(RemoteSigner.P256_SIGNATURE + blake2bhash).digest()).digest()[:4]
        return b58encode(RemoteSigner.P256_SIGNATURE + blake2bhash + shabytes).decode()

    def sign(self, test_mode=False):
        encoded_sig = ''
        blocklevel = self.get_block_level()
        info('sign() function in remote_signer now has its data to sign')
        if self.valid_block_format(self.payload):
            info('Block format is valid')
            if not self.is_generic() or self.is_generic():  # to restrict transactions, just remove the or part
                info('Preamble is valid.  level is ' + str(blocklevel))
                if ((self.is_block() or self.is_endorsement()) and self.is_within_level_threshold()) or (not self.is_block() and not self.is_endorsement()):
                    info('The request is valid.. getting signature')
                    try:
                        op = blake2b(unhexlify(self.payload), digest_size=32).digest()
                        kvurl = 'https://' + self.config['kv_name_domain'] + '.vault.azure.net'
                        sig = self.kvclient.sign(kvurl, self.kv_keyname, '', 'ES256', op).result
                        encoded_sig = RemoteSigner.b58encode_signature(sig)
                        info('Base58-encoded signature: {}'.format(encoded_sig) + ' writing DB row if bake or endorse')

                        if self.is_block() or self.is_endorsement():
                            #first write the db table
                            dbclient = cosmos_client.CosmosClient(url_connection=self.config['cosmos_host'], auth={'masterKey': self.config['cosmos_key']}, consistency_level='Strong')
                            collection_link = 'dbs/' + self.config['cosmos_db'] + ('/colls/' + self.config['cosmos_collection']).format(id)
                            container = dbclient.ReadContainer(collection_link)
                            itemtype = ''
                            if self.is_block():
                                itemtype = 'block'
                            else:
                                itemtype = 'endorse'
                            # CRITICAL  "/itemtype" VERBATIM should be set as partition key in the CosmosDB SQL table, as we will have 2 partitions: /block and /endorse, and the unique key is "/blocklevel"
                            dbclient.CreateItem(container['_self'], {'id': itemtype + str(blocklevel), 'itemtype': itemtype, 'blocklevel': blocklevel, 'baker': self.config['bakerid'], 'sig': encoded_sig})

                            # now read the table to check to prevent double
                            query = {'query': 'select c.baker from c where c.itemtype = \'' + itemtype + '\' and c.blocklevel = ' + str(blocklevel)}
                            bakerrows = dbclient.QueryItems(container['_self'], query, {'maxItemCount': 1, 'enableCrossPartitionQuery': False, 'consistencyLevel': 'Strong'})
                            for bakerrow in iter(bakerrows):
                                if bakerrow['baker'] != self.config['bakerid']:
                                    error('SHOULD BE IMPOSSIBLE WITH STRONG CONSISTENCY!  OUR WRITE SUCCEEDED BUT THEN OUR READ VERIFICATION RETURNED BAKERID DATA WE DID NOT WRITE')
                                    raise Exception('Strong Consistency Violation!')
                    except:
                        error('Error - Either another baker baked first, or possibly CosmosDB/HSM issue.')
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

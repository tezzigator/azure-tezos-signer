from logging import debug, info, error
from os import environ
from azure.functions import HttpRequest, HttpResponse
from azure.keyvault import KeyVaultClient
from msrestazure.azure_active_directory import MSIAuthentication
from hashlib import blake2b, sha256
from base58check import b58encode
from socket import gethostname
from uuid import uuid4
from json import dumps
from struct import unpack
from string import hexdigits
from binascii import unhexlify, hexlify
from hashlib import blake2b, sha256
from base64 import urlsafe_b64encode

KVURL = 'https://' + environ["FQDN"]  # this var is the HTTPS:// URL ending with just the FQDN and no trailing / character
KEYNAME = environ['NAME'] # the key name in the keyvault
TEZOS_PKHASH  = environ['PKH'] # tz....
TEZOS_PUBLICKEY  = environ['PKY'] # p2pk, etc
BAKERID = gethostname()
P2PK_MAGIC = bytes.fromhex('03b28b7f')
P2HASH_MAGIC = bytes.fromhex('06a1a4')
P256_SIGNATURE = bytes.fromhex('36f02c34')
kvclient = KeyVaultClient(MSIAuthentication(resource='https://vault.azure.net'))

def getsigningkeys():
    keys = kvclient.get_keys(KVURL)
    pubkeydat = {}
    for key in keys:
        keyname = key.kid.split('/')
        keydat = kvclient.get_key(KVURL, keyname[-1], '').key

        parity = bytes([2])
        if int.from_bytes(keydat.y, 'big') % 2 == 1:  parity = bytes([3])
        shabytes = sha256(sha256(P2PK_MAGIC + parity + keydat.x).digest()).digest()[:4]
        public_key = b58encode(P2PK_MAGIC + parity + keydat.x + shabytes).decode()
        blake2bhash = blake2b(parity + keydat.x, digest_size=20).digest()
        shabytes = sha256(sha256(P2HASH_MAGIC + blake2bhash).digest()).digest()[:4]
        pkhash = b58encode(P2HASH_MAGIC + blake2bhash + shabytes).decode()
        pubkeydat.update({pkhash:{'kv_keyname':keyname[-1], 'public_key':public_key}})
        info('Retrieved key info: kevault keyname: ' + keyname[-1] + ' pkhash: ' + pkhash + ' - public_key: ' + public_key)
    return dumps(pubkeydat)

def getsignature(payload):
    info('Now in getsignature()')
    data = all(c in hexdigits for c in payload) and bytes.fromhex(payload)
    info('The getsignature() function now has its data')
    if not all(c in hexdigits for c in payload):  
        raise Exception('Invalid payload!')
    
    level = 0
    block = False
    if (list(data)[0] == 1):
        block = True
        level = unpack('>L', unhexlify(payload[10:18]))[0]
        info('Bake request, level is ' + str(level))
    elif (list(data)[0] == 2):
        level = unpack('>L', unhexlify(payload[-8:]))[0]
        info('Endorse request, level is ' + str(level))
    else:
        info('Request to sign non bake/endorse operation not allowed!')
        raise Exception('Signing request not block/endorsement')      
    
    op = blake2b(unhexlify(payload), digest_size=32).digest()
    sig = kvclient.sign(KVURL, KEYNAME, '', 'ES256', op).result
    shabytes = sha256(sha256(P256_SIGNATURE + sig).digest()).digest()[:4]    
    encoded_sig = b58encode(P256_SIGNATURE + sig + shabytes).decode()
    info('{"signature": "' + encoded_sig + '"}')
    return '{"signature": "' + encoded_sig + '"}'

def main(req: HttpRequest) -> HttpResponse:
    try:
        if req.method == 'GET':            
            info('Signing function: a GET request.')

            if (req.route_params.get('path') == 'authorized_keys'):
                info('GET authorized_keys request, responding with {}')
                return HttpResponse('{}', headers={"Content-Type": "application/json"})

            elif (req.route_params.get('path') == 'keys') and not (req.route_params.get('pkhash')):                
                info('GET pkhashs request ')
                return HttpResponse(getsigningkeys(), headers={"Content-Type": "application/json"})

            elif (req.route_params.get('path') == 'keys') and (req.route_params.get('pkhash') == TEZOS_PKHASH):
                info('GET public_key request for ' + req.route_params.get('pkhash'))
                return HttpResponse('{"public_key": "' + TEZOS_PUBLICKEY + '"}', headers={"Content-Type": "application/json"})

            else:
                raise Exception('GET got a route that is unsupported, or couldnt fetch public key data from vault, or ENV VAR(s)missing')

        elif req.method == 'POST':
            info('Signing function: a POST request.')
            if (req.route_params.get('path') =='keys') and (req.route_params.get('pkhash') == TEZOS_PKHASH):
                info('POST signing request for ' + req.route_params.get('pkhash'))
                datatosign = req.get_body().decode('utf-8')
                info('Chunk: ' + str(len(datatosign)) + 'chars -' + datatosign + '-')
                datatosign = datatosign.strip('"')[:-2]
                info('Payload: ' + str(len(datatosign)) + 'chars -' + datatosign + '-')
                return HttpResponse(getsignature(datatosign), headers={"Content-Type": "application/json"})
            else:
                raise Exception()
                
        else:
             raise Exception('Request was not a GET or POST')

    except Exception as issue:
        info('Exception:')
        info(issue)
        info('The request was invalid, returning 404')
        return HttpResponse(str(issue),headers={"Content-Type": "text/html"}, status_code=404)


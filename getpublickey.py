#!/usr/bin/env python3

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
###########################################################

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import blake2b, sha256
from base58 import b58encode
from requests import post, get
from json import loadsimport

charenc = 'utf-8'
p2pk_magic =  bytes([3, 178, 139, 127])
p2hash_magic = bytes([6, 161, 164])
token_url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net'
kid_url = 'https://tezzigator.vault.azure.net/keys/tezzigator'

# get bearer auth token from AAD
print('fetch bearer token... ', end='')
headers = {'Metadata': 'true', 'Accept': 'application/json'}
response = get(token_url, allow_redirects=False, headers=headers)
aad_token = loads(response.text)['access_token']
print('success')

# get pubkey EC points
print('fetching public key XY coordinates...')
headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + aad_token}
response = get(kid_url + '?api-version=7.0', allow_redirects=False, headers=headers)
x_coord = loads(response.text)['key']['x']
y_coord = loads(response.text)['key']['y']
print('x: ' + x_coord)
print('y: ' + y_coord)

# determine parity in Y coord - note that Azure has stripped off any padding that may have been there, we have to check and add it back
parity = bytes([2])
if int.from_bytes(urlsafe_b64decode(y_coord + "=" * ((4 - len(y_coord) % 4) % 4)), 'big') % 2 == 1:
    parity = bytes([3])

# generate p256 public key
pubkey = parity + urlsafe_b64decode(x_coord + "=" * ((4 - len(x_coord) % 4) % 4))

# double hash the public key with the prefix
hash = sha256(sha256(p2pk_magic + pubkey).digest()).digest()[:4]

# generic blake2b hash for the shorter pkhash
genhash = blake2b(pubkey, digest_size=20).digest()

# double hash the genhash with the pkhash prefix
hashpkh = sha256(sha256(p2hash_magic + genhash).digest()).digest()[:4]

print('pubkey: ' + b58encode(p2pk_magic + pubkey + hash).decode(charenc) + '\npkhash: ' + b58encode(p2hash_magic + genhash + hashpkh).decode(charenc))

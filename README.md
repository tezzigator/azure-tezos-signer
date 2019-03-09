# Tezos Remote Signer
This is a Python app that receives remote-signer protocol formatted messages from the Tezos baking client and passes them on to an MS Azure CloudHSM to be signed.  This script will autodetect all signing keys in your keyvault and will allow for signing from clients by all keys.

## Azure Elements
VM running the tezos code, configured with a system-managed identity

CosmosDB account/database SET ITS CONSISTENCY MODEL TO 'STRONG'
* Create a SQL-collection; use '/optype' as the partition key (no quotes), use '/blocklevel' as the unique key (no quotes).

Keyvault with HSM-backed P256 key, and with a secret containing the CosmosDB account's access/pass key.
* Configure the HSM key to be able to be accessed by the VM's system-managed identity
* Configure the HSM's firewall to only be accessed by the VM's IP

## DOUBLE BAKING WARNING
MUST follow the rules above in 'Azure Elements' on the DB's settings
'Beta' only feature - true high availabiltity where 2 tezos baking nodes can be run at same time with same Azure Cloud HSM signing key

## Security Notes
This returns the signature for valid payloads, after performing some checks:
* Is the message a valid payload?
* Is the message within a certain threshold of the head of the chain? Ensures you are signing valid blocks.
* If a block/endorse operation, is the block/endorsement level already in the CosmosDB?  Prevents double bake/endorse.
* THIS CODE WILL ALLOW HSM TO SIGN TRANSACTIONS.  This can easily be restricted.

## Installation
```
virtualenv venv
source venv/bin/activate
cd venv
git clone https://github.com/tezzigator/azurehsm-signer.git
pip install -r requirements.txt
```

## Configure settings in the signer.py script
```
Python dict called 'config' at top of signer.py has a number of variables to be set.
```
## Execution
```
FLASK_APP=signer flask run
```
or
```
nohup signer.py
```
Look in the remote-signer.log file and you will see all the pkhashes of all the keys that were detected from the keyvault.
Use tezos-client to import those keys from the python signer.

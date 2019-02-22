# Tezos Remote Signer
This is a Python app that receives remote-signer protocol-formatted messages from the Tezos baking client and passes them on to an MS Azure CloudHSM to be signed.  This script will autodetect all signing keys in your keyvault and will allow for signing from clients by all keys.

## Azure Resources
This code must run on a VM in Azure, with a system-assigned managed identity which has permissions to the Keyvault.
You'll also want to lock down the Keyvault to specific VM private IPs.
Create a CosmosDB account and add a database with a colleciton using the SQL interface, SET TO STRONG CONSISTENCY.
For the CosmosDB collection you MUST use '/optype' as the partition key (no quotes).
For the CosmosDB collection you MUST use '/blocklevel' as the unique key (no quotes).

## DOUBLE BAKING WARNING
This branch has true high availabiltity as beta-test only.
MUST USE STRONG CONSISTENCY in CosmosDB noSQL database
MUST USE UNIQUE ENVIRONMENT VARIABLES 'TEZOSBAKERIR' ON EACH RUNNING BAKER

## Security Notes
This for now simply returns the signature for valid payloads, after performing some checks:
* Is the message a valid payload?
* Is the message within a certain threshold of the head of the chain? Ensures you are signing valid blocks.
* THIS CODE WILL ALLOW HSM TO SIGN TRANSACTIONS.  This can easily be restricted.


## Installation
```
virtualenv venv
source venv/bin/activate
cd venv
git clone -b high-avail https://github.com/tezzigator/azurehsm-signer.git
pip install -r requirements.txt
```

## Configure settings in the signer.py script
```
There are 5 variables to be set pertaining to keyvault/cosmos
```


## Execution
```
Export TEZOSBAKERID environment variable to be the hostname of the baker you are running on.
Obviously you must NEVER use the same name on different bakers as this is what prents doubles.
FLASK_APP=signer flask run
Look in the remote-signer.log file and you will see all the pkhashes of all the keys that were detected from the keyvault.
Use tezos-client to import those keys from the python signer.
```

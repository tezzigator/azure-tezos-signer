# Tezos Remote Signer
This is a Python app that receives messages from the Tezos baking client and passes them on to an MS Azure CloudHSM to be signed. 

## DOUBLE BAKING WARNING
Do not run this simultaneously on more than 1 baker.  True HA is not yet built into this branch.

## Security Notes
This should be considered a dev/prelim branch, no high water mark currently supported.  This branch runs on the local baker VM in Azure which should be set for system managed identity authorization to the key vault.  Also a good idea to enable the keyvault service endpoint on the subnet the VM is in.  Future branch will run with high water mark, and completely HA in the cloud.  This for now simply returns the signature for valid payloads, after performing some checks:
* Is the message a valid payload?
* THIS CODE WILL ALLOW HSM TO SIGN TRANSACTIONS.  This can easily be restricted.
* Is the message within a certain threshold of the head of the chain? Ensures you are signing valid blocks.
* For baking signatures, is the block height of the payload greater than the current block height? This prevents double baking.

## Installation
```
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Edit config.json with your credentials
```
tenant, urls, etc
```

## Find your public key and pkh
```
./getpublickey.py
```

## Go back to config.json and put in the key info
```
public and pkh
```

## Execution
```
export WEBAPP_SECRET=blah
FLASK_APP=signer flask run
```

## Running the tests
```
export WEBAPP_SECRET=blah
python -m unittest test/test_remote_signer.py
```

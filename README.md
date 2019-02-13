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

## Put in the key vault URL info in the getpublickey script
```
Key vault kid (key identifier) URL - both scripts
public and pkh key data - signer.py
```

## Find your public key and pkh
```
./getpublickey.py
```

## Put in the key info in the config section of the signer.py script
```
Key vault kid (key identifier) URL
public and pkh key data
```

## Execution
```
FLASK_APP=signer flask run
```

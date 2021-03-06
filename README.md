# Tezos Remote Signer
This is a Python app that receives remote-signer protocol formatted messages from the Tezos baking client and passes them on to an MS Azure CloudHSM to be signed.  This script will autodetect all signing keys in your keyvault's HSM and will allow for signing from clients by all keys.


## Azure Elements
* Ubuntu 18.04 VM (python3 v 3.6.7) running the tezos code, configured with a system-managed identity
* Keyvault with HSM-backed P256 key(s)
* Configure access policies for key to be able to be accessed by the VM's system-managed identity.
* Configure firewalls for key/secret to only be accessed by the VM's IP.
* Only EC signing keys should be present in this particular vault, any other keys will cause failures.


## Security Notes
This returns the signature for valid payloads, after performing some checks:
* Is the message a valid payload?
* Is the message within a certain threshold of the head of the chain? Ensures you are signing valid blocks.
* Remote hosts can only sign blocks/endorsements.  Localhost (127.0.0.1) can sign anything.

## Installation
```
virtualenv venv
source venv/bin/activate
cd venv
git clone https://github.com/tezzigator/azure-tezos-signer.git
pip install -r requirements.txt
```

## Configure settings in the signer.py script
Python dict called 'config' at top of signer.py  - set the short hostname of your keyvault here (not full FQDN)

## Execution
```
FLASK_APP=signer flask run
```
or
```
nohup python3 -u signer.py &
```
Look in the remote-signer.log file and you will see all the pkhashes of all the keys that were detected from the keyvault.
Use tezos-client to import those keys from the python signer.

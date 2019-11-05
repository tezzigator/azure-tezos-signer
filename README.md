# Tezos Remote Signer
An Azure function app that uses keys in an HSM keyvault to sign block and endorsements.
It emulates behavior by the `tezos-signer` binary, except does not support authorized_keys authentication.
This branch only allows to sign blocks or endorsements, use the branch serverless-transactions to allow all.
It is perfectly suitable for the consumption app service plan, which is the most inexpensive plan.
However you will want to cron once a minute on the baker to fetch keys to keep the function "hot"
We depend on the local baker's high water marking files for doubles prevention.

## Azure Elements
* Keyvault with HSM-backed P256 key
* Only EC signing keys should be present in this particular vault, any other keys will cause failures.
* The vault can contain multiple signing keys but the function can only sign with 1.
* Function App created with "function" level security; this is only 1 of multiple layers of security.

## Security Notes
* Configure access policies for keyvault to be able to be accessed by the function's managed identity for list & sign.
* Configure function firewall to only allow your baker VNet/subnet/IP.
* Use private service endpoint for the function in your baker subnet
* Use the `default` host key from 'Function app settings' in the tezos-client's ENV VAR:
TEZOS_SIGNER_HTTP_HEADERS=x-functions-key: <default host key>

## Installation
* Create function in the portal; configure function env variables in the `Application Settings` section of fucntion.
KVURL: URL of your keyvault; use https:// then put full FQDN but leave off trailing '/' character
KEYNAME: the key name in the keyvault
TEZOS_PKHASH: tz....
TEZOS_PUBLICKEY: p2pk, etc
* Push directly from VSCode

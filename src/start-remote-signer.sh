#!/bin/sh

###########################################################
# Written by Bo Byrd bo@tezzigator.com
# Copyright (c) 2019 Tezzigator LLC
# released under the MIT license
# most of this was actually written by Carl/Luke Youngblood
# of Blockscale, I just adapted it for MS Azure CloudHSM
###########################################################

# Starts the Tezos Remote Signer for Azure CloudHSM

start_remote_signer() {
	echo "Starting remote signer..."
	cd ~
	FLASK_APP=signer /usr/local/bin/flask run --host=0.0.0.0
}

monitor() {
	# This function monitors the CloudHSM client and remote signer and restarts them if necessary.
	while true
	do
		sleep 60
	done
}

# main

load_password
start_remote_signer
#monitor

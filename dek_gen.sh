#!/bin/bash
#
# data encryption key (DEK) gen script
# DEK is generated from data hash & code hash
#

if [ "$#" -eq 2 ] ; then
	python3 ~/CDM-Encrypter/dek_gen.py $1 $2
elif [ -e $1 ] ; then
	python3 ~/CDM-Encrypter/dek_gen.py $1
fi

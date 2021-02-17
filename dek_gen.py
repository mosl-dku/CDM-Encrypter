#
# DEK (Data Encryption Key) gen.
# DEK is generated from code hash & data hash
#

# for 3 args
# Usage: dekgen.py datafile codehash

# for 2 args
# Usage: dekgen.py datafile

import sys
import hashlib

if (len(sys.argv) == 2) :
	data_file_name = sys.argv[1]
	f = open(data_file_name, 'rb')
	data = f.read()
	f.close()
	h = hashlib.sha256(data)
	h_str = str(h.hexdigest())

	print("sha256hash: " + h_str)
	exit()
elif (len(sys.argv) == 3) :
	data_file_name = sys.argv[1]
	print("Hashing data file " + data_file_name)

	f = open(data_file_name, 'rb')
	data = f.read()
	f.close()
	h = hashlib.sha256(data)
	h_str = str(h.hexdigest())

	print("extend Hc with Hd: " + sys.argv[2] + h_str)
	combined = sys.argv[2] + h_str
	H = hashlib.sha256(combined.encode())
	H_str = str(H.hexdigest())

	res = ""
	index = 0
	for s in H_str:
		res += H_str[index]
		index += 1
		if (index % 2) == 0:
			res += " "

	print("DEK: " + res)
	exit()
else :
	print("usages:")
	print("	./dekgen.py file")
	print("		generates sha256hash for the file")
	print("	./dekgen.py datafile code_hash")
	print("		generates sha256hash from datafile and code_hash")
	exit()


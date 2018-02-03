#! /usr/bin/env python3
#-*- coding: utf-8 -*-

import os
import re
import rsa
import pickle
import hashlib

import configParser as conf

# Search fo files containing 'pattern' at the given 'path'
def search_files(pattern, path):
	result = []
	folder = os.walk(path)
	for (path, dirs, files) in folder:
		for f in files:
			if re.compile(pattern).search(f):
				result.append(os.path.join(path, f))
	return result

# Hash the file given in parameter
def hash_file(target_file):
	sha512_hash = hashlib.sha512()
	opened_file = None
	hashed_data = None
	data = None

	# Handle the errors that may happen
	try:
		opened_file = open(target_file, "rb")
		data = opened_file.read()
	except Exception as e:
		# The specified file does not exist,
		# remove from the list.
		print(target_file, ":", e)
		globals()['number_of_files_to_scan'] = \
			globals()['number_of_files_to_scan'] - 1
		del list_of_files[list_of_files.index(target_file)]
	finally:
		if data is not None:
			opened_file.close()

	if data is not None:
		sha512_hash.update(data)
		hashed_data = sha512_hash.hexdigest()

	return hashed_data

if __name__ == '__main__':
	database = {}
	database["files"] = {}
	
	# load the specific files to scan
	list_of_files = conf.FILES_TO_SCAN

	for pattern, path in conf.RULES:
		list_of_files.extend(search_files(pattern, path))
	number_of_files_to_scan = len(list_of_files)

	print("Generating database...")
	# Compute the hash values of each file
	for a_file in list_of_files:
		hash_value = hash_file(a_file)
		if hash_value is not None:
			line = a_file + ":" + hash_value + ":"
			database["files"][a_file] = hash_value

	store_database = open(conf.DATABASE, "wb")
	pickle.dump(database, store_database)
	store_database.close()

	print(number_of_files_to_scan, "files in the database.")

	# Loads the private key
	with open(conf.PRIVATE_KEY, "rb") as private_key_value:
		private_key = pickle.load(private_key_value)

	# Sign the database of hash
	with open(conf.DATABASE, 'rb') as msgfile:
		signature = rsa.sign(msgfile, private_key, 'SHA-512')

	# Writes the signature in a file.
	with open(conf.DATABASE_SIG, "wb") as signature_file:
		signature_file.write(signature)







#! /usr/bin/env python3
#-*- coding: utf-8 -*-

# importing "configParser.py" file from the same directory
import configParser as conf

# importing rsa for generating the keys
import rsa

# importing pickle to store the progress
import pickle

# generating keys randomly of length NB_BITS
print ("Generating", conf.NB_BITS, "bits RSA keys.")
pub, priv = rsa.newkeys(conf.NB_BITS)

# opening files for storing public key and private key
public_key = open(conf.PUBLIC_KEY, "wb")
private_key = open(conf.PRIVATE_KEY, "wb")

# dumping these keys into the respective files
print ("Dumping Keys")
pickle.dump(pub, public_key)
pickle.dump(priv, private_key)

# closing the opened files
public_key.close()
private_key.close()

print ("Done.")

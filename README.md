# intrusion-detection-system
Host Based IDS.  Detects all types of malicious network traffic and computer usage that can't be detected by a conventional firewall.



[ genKeys.py ]

* In rsa.newkeys() function, first parameter is the length of the public and private keys, and the second parameter is the parallel processes running for generating those random keys, as generating those keys can be time taking if the length of the keys is very large. (Refer to stored image 1.)(Source - RSA documentation - https://stuvel.eu/python-rsa-doc/usage.html)

* We used NB_BITS (length of the public and private keys) as 752 in "configFile.cfg" because for Hash Function SHA-512 minimum length of the key should be 752. (Refer to stored image 2.)(Source - RSA Documentation - https://stuvel.eu/python-rsa-doc/usage.html)


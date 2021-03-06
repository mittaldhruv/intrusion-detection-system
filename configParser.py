#! /usr/bin/env python3
#-*- coding: utf-8 -*-

import os
import configparser

# load the configuration
config = configparser.SafeConfigParser()
config.read("./configFile.cfg")

# PATH has the path to the current directory.
PATH = os.path.abspath(".")

# Length of the keys generated by RSA
NB_BITS = int(config.get('globals','nb_bits'))

# Using SMTP to send mails
MAIL_ENABLED = bool(int(config.get('email','enabled')))
MAIL_FROM = config.get('email','mail_from')
MAIL_TO = [config.get('email','mail_to')]
SMTP_SERVER = config.get('email','smtp')
USERNAME =  config.get('email','username')
PASSWORD =  config.get('email','password')

# address of the log file :
LOGS = os.path.join(PATH, "log")
# address of the database of hash values :
DATABASE = os.path.join(PATH, "database")
# address of the signature of the database:
DATABASE_SIG = os.path.join(PATH, "database.signature")
# path of the private key (to sign the database of hash values) :
PRIVATE_KEY = os.path.join(PATH, "rsa_private")
# path of the public key (to check the integrity of the database) :
PUBLIC_KEY = os.path.join(PATH, "rsa_public")


# specific files to scan :
FILES_TO_SCAN = [ \
        os.path.join(PATH, "pyIDS.py"),
        os.path.join(PATH, "configParser.py"),
        os.path.join(PATH, "configFile.cfg")]
for name, current_file in config.items("files"):
    FILES_TO_SCAN.append(current_file)

# rules to scan folders :
RULES = []
for name, rule in config.items("rules"):
    pattern, folder = rule.split(' ')
    RULES.append((pattern, folder))

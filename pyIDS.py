#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import os
import sys
import time
import pickle
import hashlib
import threading, queue
import rsa
from contextlib import contextmanager

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import configParser as conf

# lock object to protect the log file during the writing
lock = threading.Lock()

# Queue for storing the logs to be sent over mail
Q = queue.Queue()

# Return a dictionnary wich contains filenames and theirs hash value.
def load_base():
    # try to open the saved base of hash values
    database = None
    with open(conf.DATABASE, "rb") as stored_database:
        database = pickle.load(stored_database)
    return database

def compare_hash(target_file, expected_hash):
    sha512_hash = hashlib.sha512()
    opened_file = None

    # each log's line contain the local time.
    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())

    # test for safety.
    if expected_hash == "":
        globals()['warning'] = globals()['warning'] + 1
        log(local_time + " No hash value for " + target_file)

    # opening the file to test
    try:
        opened_file = open(target_file, "rb")
        data = opened_file.read()
    except:
        globals()['error'] = globals()['error'] + 1
        message = local_time + " [error] " + target_file + " does not exist. "
        log(message, True)
        if conf.MAIL_ENABLED:
            Q.put(message + "\n")
    finally:
        if opened_file is not None:
            opened_file.close()

    # now compare the hash values
    if opened_file is not None:
        sha512_hash.update(data)
        hashed_data = sha512_hash.hexdigest()

        if hashed_data == expected_hash:
            # no changes, update the log file
            log(local_time + " [notice] "  + target_file + " ok")
        else:
            # hash has changed, warning
            # update alert in the log file
            globals()['warning'] = globals()['warning'] + 1
            message = local_time + " [warning] " + target_file + " changed."

            # pyIDS log
            log(message, True)

            # reporting alert in syslog
            log_syslog(message)

            if conf.MAIL_ENABLED:
                Q.put(message + "\n")

@contextmanager
def opened_w_error(filename, mode="r"):
    try:
        f = open(filename, mode)
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()

def log(message, display=False):
    lock.acquire()
    if display:
        print(message)
    try:
        log_file.write(message+"\n")
    except Exception as e:
        print(e)
    lock.release()

def log_syslog(message):
    import syslog
    syslog.syslog("pyIDS - " + message)

# Send alert via Mail
def log_mail(mfrom, mto, message):
    msg = MIMEMultipart()
    msg['From'] = mfrom
    msg['To'] = mto
    msg['Subject'] = 'pyIDS : Alert'
    msg.attach(MIMEText(message, 'plain'))
    server = smtplib.SMTP(conf.SMTP_SERVER)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(conf.USERNAME, conf.PASSWORD)
    text = msg.as_string()
    server.sendmail(mfrom, mto, text)
    server.quit()

if __name__ == "__main__":

    # each log's line contain the local time.
    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())

    with opened_w_error(conf.PUBLIC_KEY, "rb") as (public_key_value, err):
        if err:
            print(str(err))
            exit(0)
        else:
            public_key = pickle.load(public_key_value)

    with opened_w_error(conf.DATABASE_SIG, "rb") as (signature_file, err):
        if err:
            print(str(err))
            exit(0)
        else:
            signature = signature_file.read()

    with opened_w_error(conf.DATABASE, 'rb') as (msgfile, err):
        if err:
            print(str(err))
            exit(0)
        else:
            try:
                rsa.verify(msgfile, signature, public_key)
            except rsa.pkcs1.VerificationError as e:
                log_syslog("Integrity check of the base of hashes failed.")
                print("Integrity check of the base of hashes failed.")
                exit(0)

    # open the log file
    log_file = None
    try:
        log_file = open(conf.LOGS, "a")
    except Exception as e:
        log_syslog("Something wrong happens when opening the logs: " + str(e))
        print("Something wrong happens when opening the logs: " + str(e))
        exit(0)
    log(time.strftime("[%d/%m/%y %H:%M:%S] IDS starting.", \
                           time.localtime()))

    warning, error = 0, 0

    # dictionnary containing filenames and their hash value.
    base = load_base()
    if base is None:
        print("Base of hash values can not be loaded.")
        exit(0)

    report = ""

    # Check the integrity of hashed files
    list_of_threads = []
    for file in list(base["files"].keys()):
        if os.path.exists(file):
            # threading.Thread(group=None, target=function, name=None, args=())
            thread = threading.Thread(None, compare_hash, \
                                        None, (file, base["files"][file],))
            thread.start()
            list_of_threads.append(thread)

        else:
            error = error + 1
            message = local_time + " [error] " + file + " does not exist. "
            log(message, True)
            if conf.MAIL_ENABLED:
                Q.put(message + "\n")

    # blocks the calling thread until the thread
    # whose join() method is called is terminated.
    for th in list_of_threads:
        th.join()

    while not Q.empty():
        report += Q.get(True, 0.5)

    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())
    log(local_time + " Error(s) : " + str(error))
    log(local_time + " Warning(s) : " + str(warning))
    log(local_time + " IDS finished.")

    if log_file is not None:
        log_file.close()

    if conf.MAIL_ENABLED:
        if report != "":
            message = report
        else:
            message = "A system check successfully terminated at " + local_time + "."

        for admin in conf.MAIL_TO:
            log_mail(conf.MAIL_FROM, \
                        admin, \
                        message+"\n\nHave a nice day !\n\n" + \
                        "\nThis mail was sent to :\n"+"\n".join(conf.MAIL_TO))

#!/usr/bin/python
##
## Author: Adam Ramage
##  https://github.com/ffalcinelli/django-ejabberd-bridge/blob/master/ejabberd_bridge/management/commands/ejabberd_auth.py

import sys
import logging
from logging.handlers import RotatingFileHandler
import hashlib
from struct import *

sys.stderr = open('/var/log/mongooseim/extauth4.log', 'w')
# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s %(levelname)s %(message)s',
#                     filename='/var/log/mongooseim/extauth4.log',
#                     filemode='a')

log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')

my_handler = RotatingFileHandler('/var/log/mongooseim/extauth4.log', mode='a', maxBytes=5 * 1024 * 1024,
                                 backupCount=2, encoding=None, delay=0)

my_handler.setFormatter(log_formatter)
my_handler.setLevel(logging.INFO)

app_log = logging.getLogger('root')
app_log.setLevel(logging.INFO)

app_log.addHandler(my_handler)

app_log.info('extauth script started, waiting for ejabberd requests XXXXX')

hash_func = hashlib.sha256()


def encodepw(password):
    encoded_string = password.encode()
    hash_func.update(encoded_string)
    print(hash_func.hexdigest())
    return hash_func.hexdigest()


def from_ejabberd():
    app_log.info(".")
    input_length = sys.stdin.read(2)
    app_log.info("Bytes read: " + str(len(input_length)))
    app_log.info("Input Length: " + str(input_length))
    (size,) = unpack('>h', input_length)
    return sys.stdin.read(size).split(':')


def to_ejabberd(bool):
    answer = 0
    if bool:
        answer = 1
    token = pack('>hh', 2, answer)
    sys.stdout.write(token)
    sys.stdout.flush()


def auth(username, server, password):
    app_log.info("Authentication Request: Username" + str(username) + ", Server: " + str(server) + ", Password: " + str(
        password))
    return True


def isuser(username, server):
    app_log.info("isUser Request: Username" + str(username) + ", Server" + str(server))
    return True


def setpass(username, server, password):
    app_log.info(
        "Authentication Request: Username" + str(username) + ", Server" + str(server) + ", Password" + str(password))
    return False


while True:
    # try:
    data = from_ejabberd()
    success = False
    logging.info("Auth Request - %s", data)
    if data[0] == "auth":
        success = auth(data[1], data[2], data[3])
    elif data[0] == "isuser":
        success = isuser(data[1], data[2])
    elif data[0] == "setpass":
        success = setpass(data[1], data[2], data[3])
    to_ejabberd(success)
    # except Exception as e:
    #     app_log.info("Exception: - %s", e)
